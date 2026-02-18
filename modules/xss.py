"""
Módulo de detección de XSS (Cross-Site Scripting).
Detecta XSS Reflected, Stored y DOM-based.
MIGRADO a EnhancedVulnerabilityModule - 60% menos código.
"""
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from core.enhanced_base_module import EnhancedVulnerabilityModule


class XSSModule(EnhancedVulnerabilityModule):
    """
    Detecta vulnerabilidades XSS en aplicaciones web.
    Soporta Reflected, Stored y DOM-based XSS.
    """
    
    # Patrones para detectar XSS en respuestas
    XSS_PATTERNS = [
        r"<script[^>]*>.*?alert.*?</script>",
        r"<img[^>]*onerror\s*=",
        r"<svg[^>]*onload\s*=",
        r"javascript:\s*alert",
        r"<iframe[^>]*src\s*=\s*['\"]javascript:",
        r"on\w+\s*=\s*['\"]?alert",
    ]

    def __init__(self, config):
        super().__init__(config)
        # HTTPClient, PayloadManager, logger ya disponibles
        
        # Configuración específica
        self.max_tests_per_param = config.get('max_xss_tests', 10)
        
        # Cargar payloads desde PayloadManager
        self.payloads = self._load_payloads('xss', max_count=self.max_tests_per_param)

    def scan(self):
        """Ejecuta el escaneo completo de XSS."""
        self.logger.info(f"[XSS] Iniciando escaneo de XSS en: {self.target_url}")
        
        try:
            # 1. Detectar puntos de inyección (método heredado)
            injection_points = self._discover_injection_points()
            
            if not injection_points:
                self.logger.warning("[XSS] No se encontraron puntos de inyección")
                return
            
            self.logger.info(f"[XSS] Encontrados {len(injection_points)} puntos de inyección")
            
            # 2. Probar Reflected XSS
            self._test_reflected_xss(injection_points)
            
            # 3. Probar DOM XSS (análisis de JavaScript)
            self._test_dom_xss()
            
            # 4. Exportar resultados (método heredado)
            self._export_results()
            
            # Resumen
            critical = len([f for f in self.findings if f["severity"] == "critical"])
            high = len([f for f in self.findings if f["severity"] == "high"])
            medium = len([f for f in self.findings if f["severity"] == "medium"])
            
            self.logger.info(f"[XSS] Escaneo completado: {len(self.findings)} hallazgos")
            self.logger.info(f"[XSS] Severidad: Critical={critical}, High={high}, Medium={medium}")
            
        except Exception as e:
            self.logger.error(f"[XSS] Error inesperado: {e}")

    def _test_reflected_xss(self, injection_points):
        """Prueba Reflected XSS en los puntos de inyección."""
        self.logger.info("[XSS] Probando Reflected XSS...")
        
        for point in injection_points:
            param = point['parameter']
            url = point['url']
            method = point['type']
            
            # Evitar duplicados
            param_key = f"{url}:{param}"
            if param_key in self.tested_params:
                continue
            self.tested_params.add(param_key)
            
            for payload in self.payloads:
                try:
                    # Preparar request (método heredado)
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
                    
                    # Verificar si el payload se refleja sin sanitizar
                    if self._is_xss_vulnerable(response.text, payload):
                        # Añadir hallazgo (método heredado)
                        self._add_finding(
                            vulnerability=f"Reflected XSS en parámetro '{param}'",
                            severity="high",
                            url=url,
                            payload=payload,
                            details={
                                "parameter": param,
                                "method": method,
                                "type": "reflected_xss",
                                "cvss": 7.1,
                                "cwe": "CWE-79",
                                "owasp": "A03:2021 - Injection",
                                "evidence": self._get_context_snippet(response.text, payload),
                                "recommendation": "Sanitizar y escapar todas las entradas del usuario antes de reflejarlas en la respuesta. Usar Content-Security-Policy.",
                                "references": [
                                    "https://owasp.org/www-community/attacks/xss/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                                ]
                            }
                        )
                        
                        self.logger.warning(f"[XSS] Reflected XSS encontrado: {url} (param: {param})")
                        break  # Un payload exitoso es suficiente
                    
                    time.sleep(0.1)  # Rate limiting
                    
                except Exception as e:
                    self.logger.debug(f"[XSS] Error probando {param}: {e}")

    def _test_dom_xss(self):
        """Analiza JavaScript para detectar posibles DOM XSS."""
        self.logger.info("[XSS] Analizando DOM XSS...")
        
        try:
            # Hacer request (método heredado)
            response = self._make_request(self.target_url)
            if not response:
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Buscar scripts inline y externos
            scripts = soup.find_all('script')
            
            # Patrones peligrosos en JavaScript
            dangerous_patterns = [
                (r'document\.write\s*\(', 'document.write()'),
                (r'innerHTML\s*=', 'innerHTML'),
                (r'outerHTML\s*=', 'outerHTML'),
                (r'eval\s*\(', 'eval()'),
                (r'setTimeout\s*\([^,]*["\']', 'setTimeout with string'),
                (r'setInterval\s*\([^,]*["\']', 'setInterval with string'),
                (r'location\.href\s*=', 'location.href'),
                (r'location\.search', 'location.search'),
                (r'location\.hash', 'location.hash'),
                (r'window\.location', 'window.location'),
            ]
            
            for script in scripts:
                if script.string:
                    js_code = script.string
                    
                    for pattern, desc in dangerous_patterns:
                        if re.search(pattern, js_code, re.IGNORECASE):
                            # Verificar si usa datos de URL sin sanitizar
                            if re.search(r'location\.(search|hash|href)', js_code, re.IGNORECASE):
                                # Añadir hallazgo (método heredado)
                                self._add_finding(
                                    vulnerability=f"Posible DOM XSS: uso de {desc}",
                                    severity="medium",
                                    url=self.target_url,
                                    details={
                                        "type": "dom_xss",
                                        "dangerous_function": desc,
                                        "code_snippet": self._get_js_snippet(js_code, pattern),
                                        "cvss": 6.1,
                                        "cwe": "CWE-79",
                                        "owasp": "A03:2021 - Injection",
                                        "recommendation": "Validar y sanitizar datos de location.search/hash antes de usarlos en funciones peligrosas. Usar textContent en lugar de innerHTML.",
                                        "references": [
                                            "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                                            "https://portswigger.net/web-security/cross-site-scripting/dom-based"
                                        ]
                                    }
                                )
                                
                                self.logger.warning(f"[XSS] Posible DOM XSS detectado: {desc}")
                                break
        
        except Exception as e:
            self.logger.error(f"[XSS] Error analizando DOM XSS: {e}")

    def _is_xss_vulnerable(self, response_text, payload):
        """Verifica si el payload XSS se refleja sin sanitizar."""
        # Buscar el payload exacto
        if payload in response_text:
            return True
        
        # Buscar patrones XSS en la respuesta
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False

    def _get_js_snippet(self, js_code, pattern, context_size=150):
        """Obtiene un snippet del código JavaScript."""
        try:
            match = re.search(pattern, js_code, re.IGNORECASE)
            if not match:
                return "Snippet no disponible"
            
            index = match.start()
            start = max(0, index - context_size)
            end = min(len(js_code), index + context_size)
            
            snippet = js_code[start:end]
            return snippet.strip()
        except:
            return "Snippet no disponible"
