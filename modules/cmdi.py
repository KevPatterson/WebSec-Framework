"""
Módulo de detección de Command Injection (OS Command Injection).
Detecta vulnerabilidades que permiten ejecutar comandos del sistema operativo.
MIGRADO a EnhancedVulnerabilityModule - 50% menos código.
"""
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode
from core.enhanced_base_module import EnhancedVulnerabilityModule


class CommandInjectionModule(EnhancedVulnerabilityModule):
    """Detecta vulnerabilidades de Command Injection (OS Command Injection)."""
    
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
    ]
    
    # Patrones de evidencia
    CMDI_EVIDENCE_PATTERNS = [
        r'uid=\d+\(.*?\)',
        r'gid=\d+\(.*?\)',
        r'root:.*:0:0:',
        r'/bin/bash',
        r'Volume in drive',
        r'Directory of',
        r'C:\\',
        r'<DIR>',
    ]

    def __init__(self, config):
        super().__init__(config)
        # HTTPClient, PayloadManager, logger ya disponibles

    def scan(self):
        """Ejecuta el escaneo completo de Command Injection."""
        self.logger.info(f"[CMDI] Iniciando escaneo de Command Injection en: {self.target_url}")
        
        try:
            # 1. Detectar puntos de inyección (método heredado con filtro)
            cmdi_keywords = ['cmd', 'command', 'exec', 'execute', 'run', 
                            'ping', 'host', 'ip', 'file', 'path']
            injection_points = self._discover_injection_points(keywords=cmdi_keywords)
            
            if not injection_points:
                self.logger.warning("[CMDI] No se encontraron puntos de inyección")
                return
            
            self.logger.info(f"[CMDI] Encontrados {len(injection_points)} puntos de inyección")
            
            # 2. Probar Command Injection
            self._test_command_injection(injection_points)
            
            # 3. Exportar resultados (método heredado)
            self._export_results()
            
            critical = len([f for f in self.findings if f["severity"] == "critical"])
            high = len([f for f in self.findings if f["severity"] == "high"])
            
            self.logger.info(f"[CMDI] Escaneo completado: {len(self.findings)} hallazgos")
            self.logger.info(f"[CMDI] Severidad: Critical={critical}, High={high}")
            
        except Exception as e:
            self.logger.error(f"[CMDI] Error inesperado: {e}")

    def _test_command_injection(self, injection_points):
        """Prueba Command Injection."""
        self.logger.info("[CMDI] Probando Command Injection...")
        
        for point in injection_points:
            param = point['parameter']
            url = point['url']
            method = point['type']
            
            # Evitar duplicados
            param_key = f"{url}:{param}"
            if param_key in self.tested_params:
                continue
            self.tested_params.add(param_key)
            
            # Obtener respuesta baseline (método heredado)
            try:
                baseline = self._get_baseline_response(url, method)
                baseline_text = baseline['content'] if baseline else ""
            except:
                continue
            
            for payload in self.BASIC_PAYLOADS:
                try:
                    start_time = time.time()
                    
                    # Hacer request con payload (método heredado)
                    if method == 'GET':
                        parsed = urlparse(url)
                        params = parse_qs(parsed.query)
                        params[param] = [payload]
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                        response = self._make_request(test_url)
                    else:  # POST
                        data = {param: payload}
                        response = self._make_request(url, method='POST', data=data)
                    
                    elapsed_time = time.time() - start_time
                    
                    if not response:
                        continue
                    
                    # Verificar evidencia de Command Injection
                    evidence = self._detect_cmdi_evidence(response.text)
                    
                    # Detectar time-based injection
                    is_time_based = "sleep" in payload or "timeout" in payload
                    time_delay_detected = is_time_based and elapsed_time >= 4.5
                    
                    if evidence or time_delay_detected:
                        # Añadir hallazgo (método heredado)
                        self._add_finding(
                            vulnerability=f"Command Injection en parámetro '{param}'",
                            severity="critical",
                            url=url,
                            payload=payload,
                            details={
                                "parameter": param,
                                "method": method,
                                "detection_method": "time-based" if time_delay_detected else "output-based",
                                "evidence_found": evidence if evidence else f"Time delay detected: {elapsed_time:.2f}s",
                                "response_snippet": self._get_context_snippet(response.text, evidence) if evidence else "N/A",
                                "cvss": 9.8,
                                "cwe": "CWE-78",
                                "owasp": "A03:2021 - Injection",
                                "recommendation": "Evitar ejecutar comandos del sistema con entrada del usuario. Si es necesario, usar funciones seguras con whitelist de comandos permitidos.",
                                "references": [
                                    "https://owasp.org/www-community/attacks/Command_Injection",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
                                ]
                            }
                        )
                        
                        self.logger.warning(f"[CMDI] Command Injection encontrado: {url} (param: {param})")
                        break
                    
                    time.sleep(0.2)
                    
                except Exception as e:
                    self.logger.debug(f"[CMDI] Error probando {param}: {e}")

    def _detect_cmdi_evidence(self, response_text):
        """Detecta evidencia de Command Injection en la respuesta."""
        for pattern in self.CMDI_EVIDENCE_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None
