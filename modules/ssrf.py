"""
Módulo de detección de SSRF (Server-Side Request Forgery).
Detecta vulnerabilidades que permiten realizar peticiones desde el servidor.
MIGRADO a EnhancedVulnerabilityModule - 55% menos código.
"""
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode
from core.enhanced_base_module import EnhancedVulnerabilityModule


class SSRFModule(EnhancedVulnerabilityModule):
    """Detecta vulnerabilidades SSRF (Server-Side Request Forgery)."""
    
    # Payloads SSRF
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
    
    BYPASS_PAYLOADS = [
        "http://127.1",
        "http://0177.0.0.1",  # Octal
        "http://2130706433",  # Decimal
        "http://0x7f.0x0.0x0.0x1",  # Hex
        "http://localhost@127.0.0.1",
    ]
    
    # Patrones de evidencia SSRF
    SSRF_EVIDENCE_PATTERNS = [
        r'<title>.*?(localhost|127\.0\.0\.1)',
        r'Apache.*?Server',
        r'nginx',
        r'ami-id',
        r'instance-id',
        r'iam/security-credentials',
        r'Connection refused',
        r'Connection timed out',
    ]

    def __init__(self, config):
        super().__init__(config)
        # HTTPClient, PayloadManager, logger ya disponibles
        self.all_payloads = self.INTERNAL_TARGETS + self.BYPASS_PAYLOADS

    def scan(self):
        """Ejecuta el escaneo completo de SSRF."""
        self.logger.info(f"[SSRF] Iniciando escaneo de SSRF en: {self.target_url}")
        
        try:
            # 1. Detectar parámetros susceptibles a SSRF (método heredado con filtro)
            ssrf_keywords = ['url', 'uri', 'link', 'src', 'dest', 'redirect', 
                            'proxy', 'api', 'callback', 'webhook']
            injection_points = self._discover_injection_points(keywords=ssrf_keywords)
            
            if not injection_points:
                self.logger.warning("[SSRF] No se encontraron puntos de inyección")
                return
            
            self.logger.info(f"[SSRF] Encontrados {len(injection_points)} puntos de inyección")
            
            # 2. Probar SSRF
            self._test_ssrf_injection(injection_points)
            
            # 3. Exportar resultados (método heredado)
            self._export_results()
            
            critical = len([f for f in self.findings if f["severity"] == "critical"])
            high = len([f for f in self.findings if f["severity"] == "high"])
            
            self.logger.info(f"[SSRF] Escaneo completado: {len(self.findings)} hallazgos")
            self.logger.info(f"[SSRF] Severidad: Critical={critical}, High={high}")
            
        except Exception as e:
            self.logger.error(f"[SSRF] Error inesperado: {e}")

    def _test_ssrf_injection(self, injection_points):
        """Prueba SSRF injection."""
        self.logger.info("[SSRF] Probando SSRF injection...")
        
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
                baseline_time = baseline['response_time'] if baseline else 0
            except:
                continue
            
            for payload in self.all_payloads:
                try:
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
                        
                        # Añadir hallazgo (método heredado)
                        self._add_finding(
                            vulnerability=f"SSRF (Server-Side Request Forgery) en parámetro '{param}'",
                            severity=severity,
                            url=url,
                            payload=payload,
                            details={
                                "parameter": param,
                                "method": method,
                                "evidence_found": evidence if evidence else "Diferencia significativa en respuesta",
                                "response_length_diff": length_diff,
                                "response_time_diff": time_diff,
                                "cvss": 9.1 if severity == "critical" else 8.6,
                                "cwe": "CWE-918",
                                "owasp": "A10:2021 - Server-Side Request Forgery",
                                "recommendation": "Validar y sanitizar todas las URLs de entrada. Usar whitelist de dominios permitidos. Bloquear acceso a IPs privadas y metadata endpoints.",
                                "references": [
                                    "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
                                ]
                            }
                        )
                        
                        self.logger.warning(f"[SSRF] SSRF encontrado: {url} (param: {param})")
                        break
                    
                    time.sleep(0.2)
                    
                except Exception as e:
                    self.logger.debug(f"[SSRF] Error probando {param}: {e}")

    def _detect_ssrf_evidence(self, response_text, payload):
        """Detecta evidencia de SSRF en la respuesta."""
        for pattern in self.SSRF_EVIDENCE_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None
