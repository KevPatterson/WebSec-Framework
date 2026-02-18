"""
Integración profesional con Nmap usando python-nmap
Permite ejecutar escaneos de puertos, detección de servicios y OS fingerprinting.
"""
import os
from core.external.base_runner import BaseExternalRunner

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class NmapRunner(BaseExternalRunner):
    """
    Clase para orquestar la ejecución de Nmap desde el framework.
    - Usa python-nmap para integración nativa con Python
    - Soporta escaneo de puertos, detección de servicios y OS fingerprinting
    - Maneja errores y valida instalación de nmap
    """
    
    DEFAULT_TIMEOUT = 300  # 5 minutos para escaneos completos
    
    def __init__(self, config):
        super().__init__(config)
        self.nmap_path = config.get("nmap_path", "nmap")
        
        if not NMAP_AVAILABLE:
            self.logger.error("python-nmap no está instalado. Instálalo con: pip install python-nmap")
            self.nm = None
        else:
            try:
                self.nm = nmap.PortScanner()
                self.logger.info("Nmap inicializado correctamente")
            except nmap.PortScannerError as e:
                self.logger.error(f"Error al inicializar Nmap: {e}")
                self.logger.error("Asegúrate de que nmap esté instalado en tu sistema")
                self.nm = None
    
    def is_available(self):
        """Verifica si nmap está disponible y funcional."""
        return NMAP_AVAILABLE and self.nm is not None
    
    def run(self, target, ports="1-1000", arguments="-sV", sudo=False, **kwargs):
        """
        Escanea puertos en el objetivo (implementa interfaz BaseExternalRunner).
        
        :param target: IP o hostname a escanear
        :param ports: Rango de puertos (ej: "1-1000", "80,443,8080")
        :param arguments: Argumentos de nmap (ej: "-sV" para detección de servicios)
        :param sudo: Si se requieren privilegios de root (para -O, -sS, etc.)
        :return: dict con resultados del escaneo
        """
        return self.scan_ports(target, ports, arguments, sudo)
    
    def scan_ports(self, target, ports="1-1000", arguments="-sV", sudo=False):
        """
        Escanea puertos en el objetivo.
        
        :param target: IP o hostname a escanear
        :param ports: Rango de puertos (ej: "1-1000", "80,443,8080")
        :param arguments: Argumentos de nmap (ej: "-sV" para detección de servicios)
        :param sudo: Si se requieren privilegios de root (para -O, -sS, etc.)
        :return: dict con resultados del escaneo
        """
        if not self.is_available():
            self.logger.error("Nmap no está disponible")
            return None
        
        try:
            self.logger.info(f"Escaneando {target} en puertos {ports} con argumentos: {arguments}")
            
            # Ejecutar escaneo
            self.nm.scan(hosts=target, ports=ports, arguments=arguments, sudo=sudo)
            
            results = self.parse_results(self.nm)
            
            self.logger.info(f"Escaneo completado: {len(results.get('hosts', {}))} host(s) encontrado(s)")
            return results
            
        except nmap.PortScannerError as e:
            self.logger.error(f"Error en escaneo de Nmap: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error inesperado en escaneo: {e}")
            return None
    
    def parse_results(self, nm_scanner):
        """
        Parsea resultados de nmap (implementa interfaz BaseExternalRunner).
        
        :param nm_scanner: Objeto PortScanner con resultados
        :return: dict con resultados parseados
        """
        results = {
            "scan_info": nm_scanner.scaninfo(),
            "hosts": {}
        }
        
        for host in nm_scanner.all_hosts():
            host_info = {
                "hostname": nm_scanner[host].hostname(),
                "state": nm_scanner[host].state(),
                "protocols": {},
                "os": {}
            }
            
            # Información de protocolos y puertos
            for proto in nm_scanner[host].all_protocols():
                ports_info = {}
                lport = nm_scanner[host][proto].keys()
                
                for port in lport:
                    port_data = nm_scanner[host][proto][port]
                    ports_info[port] = {
                        "state": port_data.get("state", "unknown"),
                        "name": port_data.get("name", ""),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                        "extrainfo": port_data.get("extrainfo", ""),
                        "cpe": port_data.get("cpe", "")
                    }
                
                host_info["protocols"][proto] = ports_info
            
            # Información de OS (si está disponible)
            if "osmatch" in nm_scanner[host]:
                host_info["os"]["matches"] = nm_scanner[host]["osmatch"]
            
            results["hosts"][host] = host_info
        
        return results
    
    def quick_scan(self, target):
        """
        Escaneo rápido de puertos comunes.
        
        :param target: IP o hostname a escanear
        :return: dict con resultados
        """
        common_ports = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
        return self.scan_ports(target, ports=common_ports, arguments="-sV -T4")
    
    def full_scan(self, target, detect_os=False):
        """
        Escaneo completo de todos los puertos.
        
        :param target: IP o hostname a escanear
        :param detect_os: Si se debe intentar detectar el OS (requiere sudo)
        :return: dict con resultados
        """
        args = "-sV -T4 -A" if detect_os else "-sV -T4"
        return self.scan_ports(target, ports="1-65535", arguments=args, sudo=detect_os)
    
    def service_scan(self, target, ports="1-1000"):
        """
        Escaneo enfocado en detección de servicios y versiones.
        
        :param target: IP o hostname a escanear
        :param ports: Rango de puertos
        :return: dict con resultados
        """
        return self.scan_ports(target, ports=ports, arguments="-sV -sC")
    
    def vulnerability_scan(self, target, ports="1-1000"):
        """
        Escaneo con scripts de vulnerabilidades de nmap.
        
        :param target: IP o hostname a escanear
        :param ports: Rango de puertos
        :return: dict con resultados
        """
        return self.scan_ports(target, ports=ports, arguments="-sV --script vuln")
    
    def get_open_ports_summary(self, scan_results):
        """
        Extrae un resumen de puertos abiertos de los resultados.
        
        :param scan_results: Resultados de scan_ports()
        :return: lista de dicts con puertos abiertos
        """
        if not scan_results or "hosts" not in scan_results:
            return []
        
        summary = []
        for host, host_info in scan_results["hosts"].items():
            for proto, ports in host_info.get("protocols", {}).items():
                for port, port_info in ports.items():
                    if port_info.get("state") == "open":
                        summary.append({
                            "host": host,
                            "port": port,
                            "protocol": proto,
                            "service": port_info.get("name", "unknown"),
                            "product": port_info.get("product", ""),
                            "version": port_info.get("version", "")
                        })
        
        return summary
    
    # export_results heredado de BaseExternalRunner
