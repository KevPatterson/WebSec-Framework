"""
Módulo de detección de mala configuración CORS.
Análisis profundo de configuraciones Cross-Origin Resource Sharing.
CVSS: 7.5 (High)
"""
from core.enhanced_base_module import EnhancedVulnerabilityModule
from urllib.parse import urlparse


class CORSModule(EnhancedVulnerabilityModule):
    """Módulo para detectar configuraciones inseguras de CORS."""
    
    def __init__(self, config):
        super().__init__(config)
        # HTTPClient, logger, findings, report_dir ya disponibles
    
    def scan(self):
        """Detecta configuraciones inseguras de CORS."""
        self.logger.info("=== Iniciando escaneo CORS ===")
        
        try:
            # 1. Detección de Access-Control-Allow-Origin: *
            self._check_wildcard_origin()
            
            # 2. Validación de credentials con wildcard
            self._check_credentials_with_wildcard()
            
            # 3. Análisis de métodos permitidos peligrosos
            self._check_dangerous_methods()
            
            # 4. Detección de null origin acceptance
            self._check_null_origin()
            
            # 5. Verificar reflexión de Origin arbitrario
            self._check_origin_reflection()
            
            self._export_results()
            self.logger.info(f"Escaneo CORS completado: {len(self.findings)} hallazgos")
            
        except Exception as e:
            self.logger.error(f"Error en escaneo CORS: {e}")
    
    def _check_wildcard_origin(self):
        """Detecta Access-Control-Allow-Origin: *"""
        self.logger.info("Verificando wildcard en Access-Control-Allow-Origin...")
        
        try:
            response = self._make_request(self.target_url)
            if not response:
                return
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            
            if acao == '*':
                self._add_finding(
                    vulnerability="CORS - Wildcard Origin",
                    severity="high",
                    url=self.target_url,
                    payload=None,
                    details={
                        "type": "cors_wildcard",
                        "cvss": 7.5,
                        "description": "Access-Control-Allow-Origin configurado con wildcard (*)",
                        "header": "Access-Control-Allow-Origin: *",
                        "risk": "Permite que cualquier dominio acceda a los recursos",
                        "recommendation": "Especificar dominios permitidos explícitamente en lugar de usar wildcard. Implementar whitelist de orígenes confiables.",
                        "references": [
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                            "https://portswigger.net/web-security/cors"
                        ]
                    }
                )
                self.logger.warning("CORS wildcard detectado")
        
        except Exception as e:
            self.logger.error(f"Error verificando wildcard origin: {e}")
    
    def _check_credentials_with_wildcard(self):
        """Valida credentials con wildcard."""
        self.logger.info("Verificando credentials con wildcard...")
        
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self._make_request(self.target_url, headers=headers)
            if not response:
                return
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            # Wildcard con credentials es una configuración crítica
            if acao == '*' and acac.lower() == 'true':
                self._add_finding(
                    vulnerability="CORS - Credentials with Wildcard",
                    severity="critical",
                    url=self.target_url,
                    payload=None,
                    details={
                        "type": "cors_credentials_wildcard",
                        "cvss": 9.1,
                        "description": "CORS permite credentials con wildcard origin (configuración inválida pero peligrosa)",
                        "acao": acao,
                        "acac": acac,
                        "risk": "Exposición de datos sensibles a cualquier origen",
                        "recommendation": "NUNCA usar wildcard con credentials. Especificar dominios confiables explícitamente.",
                        "references": [
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials"
                        ]
                    }
                )
                self.logger.critical("CORS credentials con wildcard detectado")
            
            # Reflexión de origin con credentials
            elif acao == 'https://evil.com' and acac.lower() == 'true':
                self._add_finding(
                    vulnerability="CORS - Origin Reflection with Credentials",
                    severity="critical",
                    url=self.target_url,
                    payload=None,
                    details={
                        "type": "cors_origin_reflection_credentials",
                        "cvss": 9.1,
                        "description": "CORS refleja cualquier origin con credentials habilitados",
                        "tested_origin": "https://evil.com",
                        "reflected_origin": acao,
                        "credentials": acac,
                        "risk": "Permite robo de datos sensibles desde dominios maliciosos",
                        "recommendation": "Implementar whitelist estricta de orígenes. No reflejar el header Origin sin validación.",
                        "references": [
                            "https://portswigger.net/web-security/cors/access-control-allow-credentials"
                        ]
                    }
                )
                self.logger.critical("CORS reflexión de origin con credentials")
        
        except Exception as e:
            self.logger.error(f"Error verificando credentials: {e}")
    
    def _check_dangerous_methods(self):
        """Analiza métodos permitidos peligrosos."""
        self.logger.info("Analizando métodos CORS permitidos...")
        
        try:
            headers = {'Origin': 'https://test.com'}
            response = self._make_request(self.target_url, method='OPTIONS', headers=headers)
            if not response:
                return
            
            acam = response.headers.get('Access-Control-Allow-Methods', '')
            
            if acam:
                dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
                found_dangerous = [m for m in dangerous_methods if m in acam.upper()]
                
                if found_dangerous:
                    self._add_finding(
                        vulnerability="CORS - Dangerous Methods Allowed",
                        severity="medium",
                        url=self.target_url,
                        payload=None,
                        details={
                            "type": "cors_dangerous_methods",
                            "cvss": 6.5,
                            "description": f"CORS permite métodos HTTP peligrosos: {', '.join(found_dangerous)}",
                            "allowed_methods": acam,
                            "dangerous_methods": found_dangerous,
                            "risk": "Permite operaciones destructivas desde otros orígenes",
                            "recommendation": "Limitar métodos CORS solo a los estrictamente necesarios (GET, POST). Evitar PUT, DELETE en recursos sensibles.",
                            "references": [
                                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods"
                            ]
                        }
                    )
                    self.logger.warning(f"Métodos peligrosos permitidos: {found_dangerous}")
        
        except Exception as e:
            self.logger.error(f"Error analizando métodos: {e}")
    
    def _check_null_origin(self):
        """Detecta aceptación de null origin."""
        self.logger.info("Verificando aceptación de null origin...")
        
        try:
            headers = {'Origin': 'null'}
            response = self._make_request(self.target_url, headers=headers)
            if not response:
                return
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            
            if acao == 'null':
                self._add_finding(
                    vulnerability="CORS - Null Origin Accepted",
                    severity="high",
                    url=self.target_url,
                    payload=None,
                    details={
                        "type": "cors_null_origin",
                        "cvss": 7.5,
                        "description": "CORS acepta origin 'null' (puede ser explotado desde sandboxed iframes)",
                        "acao": acao,
                        "risk": "Atacantes pueden usar iframes sandboxed para enviar origin null",
                        "recommendation": "Rechazar explícitamente origin 'null'. Validar que el origin sea un dominio válido.",
                        "references": [
                            "https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack"
                        ]
                    }
                )
                self.logger.warning("CORS acepta null origin")
        
        except Exception as e:
            self.logger.error(f"Error verificando null origin: {e}")
    
    def _check_origin_reflection(self):
        """Verifica reflexión de Origin arbitrario."""
        self.logger.info("Verificando reflexión de origin arbitrario...")
        
        try:
            test_origins = [
                'https://attacker.com',
                'https://evil.com',
                'https://malicious.net'
            ]
            
            for origin in test_origins:
                headers = {'Origin': origin}
                response = self._make_request(self.target_url, headers=headers)
                
                if not response:
                    continue
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                
                if acao == origin:
                    self._add_finding(
                        vulnerability="CORS - Arbitrary Origin Reflection",
                        severity="high",
                        url=self.target_url,
                        payload=origin,
                        details={
                            "type": "cors_arbitrary_origin_reflection",
                            "cvss": 7.5,
                            "description": f"CORS refleja origin arbitrario sin validación: {origin}",
                            "tested_origin": origin,
                            "reflected_origin": acao,
                            "risk": "Cualquier dominio puede acceder a los recursos",
                            "recommendation": "Implementar whitelist de dominios permitidos. No reflejar el header Origin sin validación estricta.",
                            "references": [
                                "https://portswigger.net/web-security/cors"
                            ]
                        }
                    )
                    self.logger.warning(f"Origin arbitrario reflejado: {origin}")
                    break  # Solo reportar una vez
        
        except Exception as e:
            self.logger.error(f"Error verificando reflexión de origin: {e}")
