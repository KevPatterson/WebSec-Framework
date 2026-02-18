"""
Módulo de escaneo de puertos usando Nmap.
Detecta puertos abiertos, servicios y versiones en el objetivo.
"""

import os
import json
from urllib.parse import urlparse
from datetime import datetime
from core.base_module import VulnerabilityModule
from core.logger import get_logger
from core.external.nmap_runner import NmapRunner


class PortScanModule(VulnerabilityModule):
    """
    Módulo para escaneo de puertos y detección de servicios.
    Utiliza Nmap para identificar puertos abiertos, servicios y versiones.
    """
    
    def __init__(self, config):
        super().__init__(config)
        self.logger = get_logger("port_scan")
        self.target_url = config.get("target_url")
        self.findings = []
        self.scan_results = None
        self.scan_timestamp = config.get("scan_timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.report_dir = config.get("report_dir", f"reports/scan_{self.scan_timestamp}")
        
        # Configuración de escaneo
        self.scan_type = config.get("nmap_scan_type", "quick")  # quick, full, service, vuln
        self.custom_ports = config.get("nmap_ports", None)
        self.detect_os = config.get("nmap_detect_os", False)
        
        # Inicializar NmapRunner
        self.nmap_runner = NmapRunner(config)
    
    def scan(self):
        """Ejecuta el escaneo de puertos."""
        if not self.nmap_runner.is_available():
            self.logger.error("[PortScan] Nmap no está disponible. Instala python-nmap: pip install python-nmap")
            self.logger.error("[PortScan] También asegúrate de tener nmap instalado en tu sistema")
            return
        
        # Extraer hostname/IP del target_url
        target_host = self._extract_host(self.target_url)
        if not target_host:
            self.logger.error(f"[PortScan] No se pudo extraer el host de: {self.target_url}")
            return
        
        self.logger.info(f"[PortScan] Iniciando escaneo de puertos en: {target_host}")
        self.logger.info(f"[PortScan] Tipo de escaneo: {self.scan_type}")
        
        try:
            # Ejecutar escaneo según el tipo configurado
            if self.scan_type == "quick":
                self.scan_results = self.nmap_runner.quick_scan(target_host)
            elif self.scan_type == "full":
                self.scan_results = self.nmap_runner.full_scan(target_host, detect_os=self.detect_os)
            elif self.scan_type == "service":
                ports = self.custom_ports or "1-1000"
                self.scan_results = self.nmap_runner.service_scan(target_host, ports=ports)
            elif self.scan_type == "vuln":
                ports = self.custom_ports or "1-1000"
                self.scan_results = self.nmap_runner.vulnerability_scan(target_host, ports=ports)
            else:
                self.logger.warning(f"[PortScan] Tipo de escaneo desconocido: {self.scan_type}, usando 'quick'")
                self.scan_results = self.nmap_runner.quick_scan(target_host)
            
            if not self.scan_results:
                self.logger.warning("[PortScan] No se obtuvieron resultados del escaneo")
                return
            
            # Analizar resultados y generar hallazgos
            self._analyze_results()
            
            # Exportar resultados
            self._export_results()
            
            # Resumen
            self.logger.info(f"[PortScan] Escaneo completado: {len(self.findings)} hallazgos")
            
        except Exception as e:
            self.logger.error(f"[PortScan] Error durante el escaneo: {e}")
    
    def _extract_host(self, url):
        """Extrae el hostname o IP de una URL."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname or parsed.netloc
            return host if host else url
        except Exception as e:
            self.logger.error(f"[PortScan] Error al parsear URL: {e}")
            return None
    
    def _analyze_results(self):
        """Analiza los resultados del escaneo y genera hallazgos."""
        if not self.scan_results or "hosts" not in self.scan_results:
            return
        
        for host, host_info in self.scan_results["hosts"].items():
            # Analizar puertos abiertos
            for proto, ports in host_info.get("protocols", {}).items():
                for port, port_info in ports.items():
                    if port_info.get("state") == "open":
                        self._create_port_finding(host, port, proto, port_info)
            
            # Analizar información de OS si está disponible
            if host_info.get("os", {}).get("matches"):
                self._create_os_finding(host, host_info["os"]["matches"])
    
    def _create_port_finding(self, host, port, protocol, port_info):
        """Crea un hallazgo para un puerto abierto."""
        service = port_info.get("name", "unknown")
        product = port_info.get("product", "")
        version = port_info.get("version", "")
        
        # Determinar severidad basada en el puerto y servicio
        severity = self._determine_severity(port, service, product, version)
        
        # Construir descripción
        service_desc = f"{service}"
        if product:
            service_desc += f" ({product}"
            if version:
                service_desc += f" {version}"
            service_desc += ")"
        
        finding = {
            "type": "open_port",
            "severity": severity,
            "port": port,
            "protocol": protocol,
            "service": service,
            "title": f"Puerto Abierto: {port}/{protocol} - {service_desc}",
            "description": f"Se detectó el puerto {port}/{protocol} abierto ejecutando {service_desc}",
            "recommendation": self._get_recommendation(port, service),
            "cvss": self._calculate_cvss(port, service, version),
            "evidence": {
                "host": host,
                "port": port,
                "protocol": protocol,
                "service": service,
                "product": product,
                "version": version,
                "extrainfo": port_info.get("extrainfo", ""),
                "cpe": port_info.get("cpe", "")
            }
        }
        
        self.findings.append(finding)
        self.logger.info(f"[PortScan] Puerto abierto: {host}:{port}/{protocol} - {service_desc}")
    
    def _create_os_finding(self, host, os_matches):
        """Crea un hallazgo informativo sobre el OS detectado."""
        if not os_matches:
            return
        
        # Tomar el match con mayor accuracy
        best_match = max(os_matches, key=lambda x: int(x.get("accuracy", 0)))
        
        finding = {
            "type": "os_detection",
            "severity": "info",
            "title": f"Sistema Operativo Detectado: {best_match.get('name', 'Unknown')}",
            "description": f"Nmap detectó el sistema operativo con {best_match.get('accuracy', 0)}% de precisión",
            "cvss": 0.0,
            "evidence": {
                "host": host,
                "os_name": best_match.get("name", ""),
                "accuracy": best_match.get("accuracy", ""),
                "all_matches": os_matches
            }
        }
        
        self.findings.append(finding)
        self.logger.info(f"[PortScan] OS detectado: {best_match.get('name', 'Unknown')} ({best_match.get('accuracy', 0)}%)")
    
    def _determine_severity(self, port, service, product, version):
        """Determina la severidad basada en el puerto y servicio."""
        # Puertos críticos conocidos
        critical_ports = [23, 445, 3389]  # Telnet, SMB, RDP
        high_ports = [21, 22, 25, 110, 143, 3306, 5432]  # FTP, SSH, SMTP, MySQL, PostgreSQL
        
        port_num = int(port)
        
        if port_num in critical_ports:
            return "high"
        elif port_num in high_ports:
            return "medium"
        elif service in ["telnet", "ftp", "smb", "rdp"]:
            return "high"
        elif version and "vulnerable" in version.lower():
            return "high"
        else:
            return "info"
    
    def _calculate_cvss(self, port, service, version):
        """Calcula un CVSS estimado basado en el servicio."""
        # Servicios con riesgos conocidos
        high_risk_services = {
            "telnet": 7.5,
            "ftp": 5.3,
            "smb": 7.5,
            "rdp": 7.5,
            "mysql": 5.3,
            "postgresql": 5.3
        }
        
        return high_risk_services.get(service.lower(), 0.0)
    
    def _get_recommendation(self, port, service):
        """Genera recomendaciones específicas por servicio."""
        recommendations = {
            "telnet": "Deshabilitar Telnet y usar SSH en su lugar (puerto 22 con autenticación por clave)",
            "ftp": "Usar SFTP o FTPS en lugar de FTP plano. Deshabilitar anonymous login",
            "smb": "Asegurar SMB: deshabilitar SMBv1, usar autenticación fuerte, limitar acceso por firewall",
            "rdp": "Asegurar RDP: usar autenticación de dos factores, limitar acceso por IP, usar VPN",
            "mysql": "Asegurar MySQL: cambiar puerto por defecto, usar contraseñas fuertes, limitar acceso remoto",
            "postgresql": "Asegurar PostgreSQL: configurar pg_hba.conf correctamente, usar SSL, contraseñas fuertes",
            "ssh": "Asegurar SSH: deshabilitar root login, usar autenticación por clave, cambiar puerto por defecto",
            "http": "Asegurar HTTP: usar HTTPS (443), implementar security headers, mantener servidor actualizado",
            "https": "Verificar configuración SSL/TLS: usar TLS 1.2+, certificados válidos, cipher suites seguros"
        }
        
        service_lower = service.lower()
        if service_lower in recommendations:
            return recommendations[service_lower]
        else:
            return f"Verificar que el servicio {service} en el puerto {port} esté correctamente configurado y actualizado"
    
    def _export_results(self):
        """Exporta los resultados del escaneo."""
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            
            # Exportar hallazgos
            output_data = {
                "scan_info": {
                    "target": self.target_url,
                    "timestamp": self.scan_timestamp,
                    "module": "port_scan",
                    "scan_type": self.scan_type,
                    "total_findings": len(self.findings)
                },
                "scan_results": self.scan_results,
                "findings": self.findings,
                "summary": {
                    "high": len([f for f in self.findings if f["severity"] == "high"]),
                    "medium": len([f for f in self.findings if f["severity"] == "medium"]),
                    "low": len([f for f in self.findings if f["severity"] == "low"]),
                    "info": len([f for f in self.findings if f["severity"] == "info"])
                }
            }
            
            # Exportar JSON de hallazgos
            findings_path = os.path.join(self.report_dir, "port_scan_findings.json")
            with open(findings_path, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"[PortScan] Hallazgos exportados en: {findings_path}")
            
            # Exportar resultados completos de nmap
            nmap_path = os.path.join(self.report_dir, "nmap_scan_results.json")
            self.nmap_runner.export_results(self.scan_results, nmap_path)
            
        except Exception as e:
            self.logger.error(f"[PortScan] Error al exportar resultados: {e}")
    
    def get_results(self):
        """Devuelve los hallazgos encontrados."""
        return self.findings
