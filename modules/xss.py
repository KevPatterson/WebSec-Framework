"""
Módulo de detección de XSS (Cross-Site Scripting).
Detecta XSS Reflected, Stored y DOM-based.
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


class XSSModule(VulnerabilityModule):
    """
    Detecta vulnerabilidades XSS en aplicaciones web.
    Soporta Reflected, Stored y DOM-based XSS.
    """
    
    # Payloads de prueba organizados por tipo
    BASIC_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src=\"javascript:alert('XSS')\">",
    ]
    
    ADVANCED_PAYLOADS = [
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "<img/src=x onerror=alert('XSS')>",
        "<svg/onload=alert`XSS`>",
        "\" onload=alert('XSS') x=\"",
        "' onload=alert('XSS') x='",
    ]
    
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
        self.logger = get_logger("xss_module")
        self.target_url = config.get("target_url")
        self.findings = []
        self.tested_params = set()
        self.scan_timestamp = config.get("scan_timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.report_dir = config.get("report_dir", f"reports/scan_{self.scan_timestamp}")
        
        # Cargar payloads desde archivo
        self.payloads = self._load_payloads()
        
        # Configuración
        self.timeout = config.get("timeout", 10)
        self.max_payloads = config.get("max_xss_payloads", 10)  # Limitar para eficiencia

    def _load_payloads(self):
        """Carga payloads desde archivo."""
        payloads = []
        payload_file = "payloads/xss.txt"
        
        try:
            if os.path.exists(payload_file):
                with open(payload_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            payloads.append(line)
                self.logger.info(f"[XSS] Cargados {len(payloads)} payloads desde {payload_file}")
            else:
                self.logger.warning(f"[XSS] Archivo de payloads no encontrado: {payload_file}")
                payloads = self.BASIC_PAYLOADS + self.ADVANCED_PAYLOADS
        except Exception as e:
            self.logger.error(f"[XSS] Error cargando payloads: {e}")
            payloads = self.BASIC_PAYLOADS + self.ADVANCED_PAYLOADS
        
        return payloads[:self.max_payloads]  # Limitar cantidad

    def scan(self):
        """Ejecuta el escaneo completo de XSS."""
        self.logger.info(f"[XSS] Iniciando escaneo de XSS en: {self.target_url}")
        
        try:
            # 1. Detectar puntos de inyección (parámetros GET/POST, formularios)
            injection_points = self._discover_injection_points()
            
            if not injection_points:
                self.logger.warning("[XSS] No se encontraron puntos de inyección")
                return
            
            self.logger.info(f"[XSS] Encontrados {len(injection_points)} puntos de inyección")
            
            # 2. Probar Reflected XSS
            self._test_reflected_xss(injection_points)
            
            # 3. Probar DOM XSS (análisis de JavaScript)
            self._test_dom_xss()
            
            # 4. Exportar resultados
            self._export_results()
            
            # Resumen
            critical = len([f for f in self.findings if f["severity"] == "critical"])
            high = len([f for f in self.findings if f["severity"] == "high"])
            medium = len([f for f in self.findings if f["severity"] == "medium"])
            
            self.logger.info(f"[XSS] Escaneo completado: {len(self.findings)} hallazgos")
            self.logger.info(f"[XSS] Severidad: Critical={critical}, High={high}, Medium={medium}")
            
        except Exception as e:
            self.logger.error(f"[XSS] Error inesperado: {e}")

    def _discover_injection_points(self):
        """Descubre puntos de inyección (parámetros GET, formularios)."""
        injection_points = []
        
        try:
            # Obtener página principal
            response = requests.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. Parámetros GET de la URL
            parsed = urlparse(self.target_url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    injection_points.append({
                        'type': 'GET',
                        'url': self.target_url,
                        'param': param,
                        'method': 'GET'
                    })
            
            # 2. Formularios HTML
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'get').upper()
                action_url = urljoin(self.target_url, action) if action else self.target_url
                
                inputs = form.find_all(['input', 'textarea'])
                for inp in inputs:
                    name = inp.get('name')
                    if name:
                        injection_points.append({
                            'type': 'FORM',
                            'url': action_url,
                            'param': name,
                            'method': method,
                            'form': form
                        })
            
            self.logger.info(f"[XSS] Descubiertos {len(injection_points)} puntos de inyección")
            
        except Exception as e:
            self.logger.error(f"[XSS] Error descubriendo puntos de inyección: {e}")
        
        return injection_points

    def _test_reflected_xss(self, injection_points):
        """Prueba Reflected XSS en los puntos de inyección."""
        self.logger.info("[XSS] Probando Reflected XSS...")
        
        for point in injection_points:
            param_key = f"{point['url']}:{point['param']}"
            if param_key in self.tested_params:
                continue
            
            self.tested_params.add(param_key)
            
            for payload in self.payloads:
                try:
                    # Preparar request
                    if point['method'] == 'GET':
                        parsed = urlparse(point['url'])
                        params = parse_qs(parsed.query)
                        params[point['param']] = [payload]
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"
                        response = requests.get(test_url, timeout=self.timeout, allow_redirects=True)
                        
                    else:  # POST
                        data = {point['param']: payload}
                        response = requests.post(point['url'], data=data, timeout=self.timeout, allow_redirects=True)
                    
                    # Verificar si el payload se refleja sin sanitizar
                    if self._is_xss_vulnerable(response.text, payload):
                        finding = {
                            "type": "reflected_xss",
                            "severity": "high",
                            "title": f"Reflected XSS en parámetro '{point['param']}'",
                            "description": f"El parámetro '{point['param']}' es vulnerable a Reflected XSS. El payload se refleja sin sanitización adecuada.",
                            "cvss": 7.1,
                            "cwe": "CWE-79",
                            "owasp": "A03:2021 - Injection",
                            "recommendation": "Sanitizar y escapar todas las entradas del usuario antes de reflejarlas en la respuesta. Usar Content-Security-Policy.",
                            "references": [
                                "https://owasp.org/www-community/attacks/xss/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                            ],
                            "evidence": {
                                "url": point['url'],
                                "parameter": point['param'],
                                "method": point['method'],
                                "payload": payload,
                                "vulnerable": True,
                                "response_snippet": self._get_context_snippet(response.text, payload)
                            }
                        }
                        
                        self.findings.append(finding)
                        self.logger.warning(f"[XSS] Reflected XSS encontrado: {point['url']} (param: {point['param']})")
                        break  # Un payload exitoso es suficiente
                    
                    time.sleep(0.1)  # Rate limiting
                    
                except Exception as e:
                    self.logger.debug(f"[XSS] Error probando {point['param']}: {e}")

    def _test_dom_xss(self):
        """Analiza JavaScript para detectar posibles DOM XSS."""
        self.logger.info("[XSS] Analizando DOM XSS...")
        
        try:
            response = requests.get(self.target_url, timeout=self.timeout)
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
                                finding = {
                                    "type": "dom_xss",
                                    "severity": "medium",
                                    "title": f"Posible DOM XSS: uso de {desc}",
                                    "description": f"El código JavaScript usa {desc} con datos potencialmente controlables por el usuario (location.search/hash). Esto puede llevar a DOM XSS.",
                                    "cvss": 6.1,
                                    "cwe": "CWE-79",
                                    "owasp": "A03:2021 - Injection",
                                    "recommendation": "Validar y sanitizar datos de location.search/hash antes de usarlos en funciones peligrosas. Usar textContent en lugar de innerHTML.",
                                    "references": [
                                        "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                                        "https://portswigger.net/web-security/cross-site-scripting/dom-based"
                                    ],
                                    "evidence": {
                                        "url": self.target_url,
                                        "dangerous_function": desc,
                                        "code_snippet": self._get_js_snippet(js_code, pattern)
                                    }
                                }
                                
                                self.findings.append(finding)
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

    def _get_context_snippet(self, text, payload, context_size=100):
        """Obtiene un snippet del contexto donde aparece el payload."""
        try:
            index = text.find(payload)
            if index == -1:
                return "Payload reflejado (contexto no disponible)"
            
            start = max(0, index - context_size)
            end = min(len(text), index + len(payload) + context_size)
            
            snippet = text[start:end]
            return f"...{snippet}..."
        except:
            return "Contexto no disponible"

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

    def _export_results(self):
        """Exporta los hallazgos a JSON."""
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            
            output_data = {
                "scan_info": {
                    "target": self.target_url,
                    "timestamp": self.scan_timestamp,
                    "module": "xss",
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
            
            output_path = os.path.join(self.report_dir, "xss_findings.json")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"[XSS] Resultados exportados en: {output_path}")
            
        except Exception as e:
            self.logger.error(f"[XSS] Error al exportar resultados: {e}")

    def get_results(self):
        """Devuelve los hallazgos encontrados."""
        return self.findings
