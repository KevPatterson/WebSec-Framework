"""
Módulo de detección de CSRF (Cross-Site Request Forgery).
Detecta vulnerabilidades de falsificación de peticiones entre sitios.
CVSS: 8.8 (High)
"""
from core.enhanced_base_module import EnhancedVulnerabilityModule
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


class CSRFModule(EnhancedVulnerabilityModule):
    """Módulo para detectar vulnerabilidades CSRF (Cross-Site Request Forgery)."""
    
    def __init__(self, config):
        super().__init__(config)
        # HTTPClient, logger, findings, report_dir ya disponibles
    
    def scan(self):
        """Ejecuta el escaneo de CSRF."""
        self.logger.info("=== Iniciando escaneo CSRF ===")
        
        try:
            # 1. Análisis de tokens CSRF en formularios
            self._check_csrf_tokens()
            
            # 2. Validación de SameSite cookies
            self._check_samesite_cookies()
            
            # 3. Verificación de headers Origin/Referer
            self._check_origin_referer_validation()
            
            # 4. Detección de endpoints sin protección
            self._check_unprotected_endpoints()
            
            self._export_results()
            self.logger.info(f"Escaneo CSRF completado: {len(self.findings)} hallazgos")
            
        except Exception as e:
            self.logger.error(f"Error en escaneo CSRF: {e}")
    
    def _check_csrf_tokens(self):
        """Analiza formularios en busca de tokens CSRF."""
        self.logger.info("Analizando tokens CSRF en formularios...")
        
        try:
            response = self._make_request(self.target_url)
            if not response:
                return
            
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                self.logger.info("No se encontraron formularios para analizar")
                return
            
            for idx, form in enumerate(forms):
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').upper()
                
                # Solo analizar formularios POST
                if form_method != 'POST':
                    continue
                
                # Buscar tokens CSRF comunes
                csrf_token_found = False
                token_names = ['csrf', 'csrf_token', 'csrftoken', '_csrf', 'token', 
                              'authenticity_token', '_token', 'csrf-token']
                
                inputs = form.find_all('input')
                for input_tag in inputs:
                    input_name = input_tag.get('name', '').lower()
                    input_type = input_tag.get('type', '').lower()
                    
                    if any(token in input_name for token in token_names):
                        csrf_token_found = True
                        break
                
                if not csrf_token_found:
                    full_action = urljoin(self.target_url, form_action)
                    
                    self._add_finding(
                        vulnerability="CSRF - Missing Token",
                        severity="high",
                        url=full_action,
                        payload=None,
                        details={
                            "type": "csrf_missing_token",
                            "cvss": 8.8,
                            "method": form_method,
                            "description": f"Formulario sin token CSRF detectado",
                            "form_index": idx,
                            "form_action": form_action,
                            "form_method": form_method,
                            "inputs_count": len(inputs),
                            "recommendation": "Implementar tokens CSRF en todos los formularios POST. Usar librerías como Flask-WTF, Django CSRF, o implementar tokens únicos por sesión.",
                            "references": [
                                "https://owasp.org/www-community/attacks/csrf",
                                "https://cwe.mitre.org/data/definitions/352.html"
                            ]
                        }
                    )
                    self.logger.warning(f"Formulario sin token CSRF: {full_action}")
        
        except Exception as e:
            self.logger.error(f"Error analizando tokens CSRF: {e}")
    
    def _check_samesite_cookies(self):
        """Valida el atributo SameSite en cookies."""
        self.logger.info("Validando atributo SameSite en cookies...")
        
        try:
            response = self._make_request(self.target_url)
            if not response:
                return
            
            cookies = response.cookies
            
            if not cookies:
                self.logger.info("No se encontraron cookies para analizar")
                return
            
            for cookie in cookies:
                cookie_name = cookie.name
                
                # Verificar si tiene SameSite
                has_samesite = False
                samesite_value = None
                
                # Intentar obtener el valor de SameSite
                if hasattr(cookie, '_rest') and 'SameSite' in cookie._rest:
                    has_samesite = True
                    samesite_value = cookie._rest.get('SameSite')
                
                # Verificar Set-Cookie header directamente
                set_cookie_header = response.headers.get('Set-Cookie', '')
                if 'SameSite' in set_cookie_header:
                    has_samesite = True
                    match = re.search(r'SameSite=(\w+)', set_cookie_header, re.IGNORECASE)
                    if match:
                        samesite_value = match.group(1)
                
                if not has_samesite:
                    self._add_finding(
                        vulnerability="CSRF - Missing SameSite Cookie Attribute",
                        severity="medium",
                        url=self.target_url,
                        payload=None,
                        details={
                            "type": "csrf_missing_samesite",
                            "cvss": 6.5,
                            "description": f"Cookie '{cookie_name}' sin atributo SameSite",
                            "cookie_name": cookie_name,
                            "secure": cookie.secure,
                            "httponly": cookie.has_nonstandard_attr('HttpOnly'),
                            "recommendation": "Configurar SameSite=Strict o SameSite=Lax en todas las cookies de sesión para prevenir CSRF.",
                            "references": [
                                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                            ]
                        }
                    )
                    self.logger.warning(f"Cookie sin SameSite: {cookie_name}")
                
                elif samesite_value and samesite_value.lower() == 'none' and not cookie.secure:
                    self._add_finding(
                        vulnerability="CSRF - Insecure SameSite=None Cookie",
                        severity="high",
                        url=self.target_url,
                        payload=None,
                        details={
                            "type": "csrf_insecure_samesite_none",
                            "cvss": 7.5,
                            "description": f"Cookie '{cookie_name}' con SameSite=None sin Secure flag",
                            "cookie_name": cookie_name,
                            "samesite": samesite_value,
                            "secure": cookie.secure,
                            "recommendation": "Cookies con SameSite=None deben tener el flag Secure activado.",
                            "references": [
                                "https://web.dev/samesite-cookies-explained/"
                            ]
                        }
                    )
                    self.logger.warning(f"Cookie insegura SameSite=None: {cookie_name}")
        
        except Exception as e:
            self.logger.error(f"Error validando SameSite cookies: {e}")
    
    def _check_origin_referer_validation(self):
        """Verifica validación de headers Origin/Referer."""
        self.logger.info("Verificando validación de Origin/Referer...")
        
        try:
            # Probar con Origin malicioso
            malicious_origins = [
                'https://evil.com',
                'https://attacker.com',
                'null'
            ]
            
            test_endpoints = [
                self.target_url,
                urljoin(self.target_url, '/login'),
                urljoin(self.target_url, '/api'),
            ]
            
            for endpoint in test_endpoints:
                for origin in malicious_origins:
                    try:
                        headers = {'Origin': origin}
                        response = self._make_request(endpoint, method='POST', headers=headers)

                        if not response:
                            continue
                        
                        # CRÍTICO: Filtrar endpoints que no existen (404)
                        if response.status_code == 404:
                            self.logger.debug(f"[CSRF] Endpoint {endpoint} devuelve 404 - no existe")
                            break  # No probar más origins en este endpoint
                        
                        # CRÍTICO: Solo reportar endpoints que responden correctamente
                        # Si acepta el request sin validar Origin Y el endpoint existe
                        if response.status_code in [200, 201, 204]:
                            self._add_finding(
                                vulnerability="CSRF - Missing Origin/Referer Validation",
                                severity="high",
                                url=endpoint,
                                payload=origin,
                                details={
                                    "type": "csrf_missing_origin_validation",
                                    "cvss": 8.1,
                                    "method": "POST",
                                    "description": f"Endpoint acepta peticiones con Origin malicioso: {origin}",
                                    "malicious_origin": origin,
                                    "status_code": response.status_code,
                                    "endpoint": endpoint,
                                    "recommendation": "Implementar validación estricta de headers Origin y Referer en endpoints sensibles.",
                                    "references": [
                                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
                                    ]
                                }
                            )
                            self.logger.warning(f"Endpoint sin validación Origin: {endpoint}")
                            break  # Solo reportar una vez por endpoint
                    
                    except Exception:
                        pass  # Endpoint no existe o no responde
        
        except Exception as e:
            self.logger.error(f"Error verificando Origin/Referer: {e}")
    
    def _check_unprotected_endpoints(self):
        """Detecta endpoints sin protección CSRF."""
        self.logger.info("Detectando endpoints sin protección CSRF...")
        
        try:
            # Endpoints comunes que deberían tener protección CSRF
            sensitive_endpoints = [
                '/api/user/update',
                '/api/password/change',
                '/api/email/change',
                '/api/delete',
                '/profile/update',
                '/settings/update',
                '/account/delete'
            ]
            
            for endpoint in sensitive_endpoints:
                full_url = urljoin(self.target_url, endpoint)
                
                try:
                    # Intentar POST sin token CSRF
                    response = self._make_request(full_url, method='POST', data={'test': 'data'})
                    
                    if not response:
                        continue
                    
                    # Si no rechaza la petición (403/401), podría ser vulnerable
                    if response.status_code not in [403, 401, 404]:
                        self._add_finding(
                            vulnerability="CSRF - Unprotected Endpoint",
                            severity="high",
                            url=full_url,
                            payload=None,
                            details={
                                "type": "csrf_unprotected_endpoint",
                                "cvss": 8.8,
                                "method": "POST",
                                "description": f"Endpoint sensible sin protección CSRF aparente",
                                "status_code": response.status_code,
                                "endpoint": endpoint,
                                "recommendation": "Implementar protección CSRF en todos los endpoints que modifican datos.",
                                "references": [
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery"
                                ]
                            }
                        )
                        self.logger.warning(f"Endpoint sin protección CSRF: {full_url}")
                
                except Exception:
                    pass  # Endpoint no existe
        
        except Exception as e:
            self.logger.error(f"Error detectando endpoints desprotegidos: {e}")
