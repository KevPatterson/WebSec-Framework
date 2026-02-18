"""
Módulo de detección de autenticación débil.
Detecta problemas de autenticación, credenciales por defecto y configuraciones inseguras.
"""

from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from core.enhanced_base_module import EnhancedVulnerabilityModule
from datetime import datetime
import re
import time
import base64


class AuthModule(EnhancedVulnerabilityModule):
    """
    Detecta vulnerabilidades de autenticación débil, credenciales por defecto,
    y configuraciones inseguras de autenticación.
    """
    
    # Credenciales comunes por defecto
    DEFAULT_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("root", "root"),
        ("root", "password"),
        ("administrator", "administrator"),
        ("user", "user"),
        ("test", "test"),
        ("guest", "guest"),
        ("admin", ""),
        ("", "admin"),
    ]
    
    # Patrones de formularios de login
    LOGIN_FORM_PATTERNS = [
        r'login',
        r'signin',
        r'log-in',
        r'sign-in',
        r'authenticate',
        r'auth',
    ]
    
    # Patrones de éxito de login
    SUCCESS_PATTERNS = [
        r'welcome',
        r'dashboard',
        r'logout',
        r'sign out',
        r'profile',
        r'account',
        r'successfully logged in',
        r'authentication successful',
    ]
    
    # Headers de autenticación débil
    WEAK_AUTH_HEADERS = [
        'WWW-Authenticate',
        'Authorization',
    ]

    def __init__(self, config):
        super().__init__(config)
        # HTTPClient, logger, findings, report_dir ya disponibles
        self.tested_forms = set()
        self.scan_timestamp = config.get("scan_timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.timeout = config.get("timeout", 10)

    def scan(self):
        """Ejecuta el escaneo completo de autenticación."""
        self.logger.info(f"[AUTH] Iniciando escaneo de autenticación en: {self.target_url}")
        
        try:
            # 1. Detectar autenticación HTTP Basic/Digest
            self._check_http_auth()
            
            # 2. Buscar formularios de login
            login_forms = self._discover_login_forms()
            
            if login_forms:
                self.logger.info(f"[AUTH] Encontrados {len(login_forms)} formularios de login")
                
                # 3. Probar credenciales por defecto
                self._test_default_credentials(login_forms)
                
                # 4. Verificar protecciones contra fuerza bruta
                self._check_brute_force_protection(login_forms)
            else:
                self.logger.warning("[AUTH] No se encontraron formularios de login")
            
            # 5. Verificar configuraciones inseguras
            self._check_insecure_configs()
            
            # 6. Exportar resultados (método heredado)
            self._export_results()
            
            # Resumen
            critical = len([f for f in self.findings if f.get("severity") == "critical"])
            high = len([f for f in self.findings if f.get("severity") == "high"])
            medium = len([f for f in self.findings if f.get("severity") == "medium"])
            
            self.logger.info(f"[AUTH] Escaneo completado: {len(self.findings)} hallazgos")
            self.logger.info(f"[AUTH] Severidad: Critical={critical}, High={high}, Medium={medium}")
            
        except Exception as e:
            self.logger.error(f"[AUTH] Error inesperado: {e}")

    def _check_http_auth(self):
        """Verifica autenticación HTTP Basic/Digest."""
        try:
            response = self._make_request(self.target_url)
            
            if not response:
                return
            
            # Verificar si requiere autenticación HTTP
            if response.status_code == 401:
                auth_header = response.headers.get('WWW-Authenticate', '')
                
                if 'Basic' in auth_header:
                    self._add_finding(
                        vulnerability="Autenticación HTTP Basic detectada",
                        severity="medium",
                        url=self.target_url,
                        payload=None,
                        details={
                            "type": "weak_authentication",
                            "cvss": 5.3,
                            "cwe": "CWE-319",
                            "owasp": "A07:2021 - Identification and Authentication Failures",
                            "description": "El sitio utiliza autenticación HTTP Basic, que transmite credenciales en Base64 (fácilmente decodificable). Sin HTTPS, las credenciales se envían en texto plano.",
                            "auth_type": "HTTP Basic",
                            "header": auth_header,
                            "vulnerable": True,
                            "recommendation": "Usar HTTPS obligatorio con autenticación basada en tokens (JWT, OAuth2) o sesiones seguras. Evitar HTTP Basic en producción.",
                            "references": [
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                            ]
                        }
                    )
                    self.logger.warning("[AUTH] Autenticación HTTP Basic detectada")
                    
                    # Probar credenciales por defecto en HTTP Basic
                    self._test_http_basic_defaults()
                
        except Exception as e:
            self.logger.debug(f"[AUTH] Error verificando HTTP auth: {e}")

    def _test_http_basic_defaults(self):
        """Prueba credenciales por defecto en HTTP Basic."""
        for username, password in self.DEFAULT_CREDENTIALS[:5]:  # Limitar intentos
            try:
                response = requests.get(
                    self.target_url,
                    auth=(username, password),
                    timeout=self.timeout
                )
                
                if response.status_code == 200:
                    self._add_finding(
                        vulnerability=f"Credenciales por defecto en HTTP Basic: {username}:{password}",
                        severity="critical",
                        url=self.target_url,
                        payload=f"{username}:{password}",
                        details={
                            "type": "default_credentials",
                            "cvss": 9.8,
                            "cwe": "CWE-798",
                            "owasp": "A07:2021 - Identification and Authentication Failures",
                            "description": f"El sitio acepta credenciales por defecto '{username}:{password}' en autenticación HTTP Basic. Esto permite acceso no autorizado.",
                            "username": username,
                            "password": password,
                            "vulnerable": True,
                            "recommendation": "Cambiar inmediatamente todas las credenciales por defecto. Implementar política de contraseñas fuertes y autenticación multifactor.",
                            "references": [
                                "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                                "https://cwe.mitre.org/data/definitions/798.html"
                            ]
                        }
                    )
                    self.logger.critical(f"[AUTH] Credenciales por defecto funcionan: {username}:{password}")
                    return  # Una credencial exitosa es suficiente
                
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.debug(f"[AUTH] Error probando credenciales HTTP Basic: {e}")

    def _discover_login_forms(self):
        """Descubre formularios de login."""
        login_forms = []
        
        try:
            response = self._make_request(self.target_url)
            if not response:
                return login_forms
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Buscar formularios
            forms = soup.find_all('form')
            
            for form in forms:
                # Verificar si es un formulario de login
                form_text = str(form).lower()
                action = form.get('action', '')
                
                is_login_form = any(
                    re.search(pattern, form_text) 
                    for pattern in self.LOGIN_FORM_PATTERNS
                )
                
                if is_login_form:
                    method = form.get('method', 'post').upper()
                    action_url = urljoin(self.target_url, action) if action else self.target_url
                    
                    # Extraer campos del formulario
                    fields = {}
                    inputs = form.find_all(['input', 'textarea'])
                    
                    for inp in inputs:
                        name = inp.get('name')
                        input_type = inp.get('type', 'text').lower()
                        
                        if name:
                            fields[name] = {
                                'type': input_type,
                                'value': inp.get('value', '')
                            }
                    
                    login_forms.append({
                        'url': action_url,
                        'method': method,
                        'fields': fields
                    })
            
            # Buscar páginas de login comunes
            common_login_paths = [
                '/login',
                '/signin',
                '/admin',
                '/admin/login',
                '/user/login',
                '/auth/login',
            ]
            
            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            for path in common_login_paths:
                try:
                    test_url = urljoin(base_url, path)
                    resp = self._make_request(test_url)
                    
                    if not resp or resp.status_code != 200:
                        continue
                    
                    soup = BeautifulSoup(resp.text, 'html.parser')
                    forms = soup.find_all('form')
                    
                    for form in forms:
                        method = form.get('method', 'post').upper()
                        action = form.get('action', '')
                        action_url = urljoin(test_url, action) if action else test_url
                        
                        fields = {}
                        inputs = form.find_all(['input', 'textarea'])
                        
                        for inp in inputs:
                            name = inp.get('name')
                            if name:
                                fields[name] = {
                                    'type': inp.get('type', 'text').lower(),
                                    'value': inp.get('value', '')
                                }
                        
                        if fields:
                            login_forms.append({
                                'url': action_url,
                                'method': method,
                                'fields': fields
                            })
                except:
                    pass
            
            self.logger.info(f"[AUTH] Descubiertos {len(login_forms)} formularios de login")
            
        except Exception as e:
            self.logger.error(f"[AUTH] Error descubriendo formularios de login: {e}")
        
        return login_forms

    def _test_default_credentials(self, login_forms):
        """Prueba credenciales por defecto en formularios."""
        self.logger.info("[AUTH] Probando credenciales por defecto...")
        
        for form in login_forms:
            form_key = f"{form['url']}:{form['method']}"
            if form_key in self.tested_forms:
                continue
            
            self.tested_forms.add(form_key)
            
            # Identificar campos de usuario y contraseña
            username_field = None
            password_field = None
            
            for field_name, field_info in form['fields'].items():
                field_lower = field_name.lower()
                field_type = field_info['type']
                
                if field_type == 'password':
                    password_field = field_name
                elif any(keyword in field_lower for keyword in ['user', 'login', 'email', 'account']):
                    username_field = field_name
            
            if not (username_field and password_field):
                continue
            
            # Probar credenciales por defecto
            for username, password in self.DEFAULT_CREDENTIALS[:5]:  # Limitar intentos
                try:
                    data = form['fields'].copy()
                    data[username_field] = {'value': username}
                    data[password_field] = {'value': password}
                    
                    # Preparar datos para envío
                    post_data = {k: v['value'] for k, v in data.items()}
                    
                    response = requests.request(
                        form['method'],
                        form['url'],
                        data=post_data,
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                    
                    # Verificar si el login fue exitoso
                    if self._is_login_successful(response):
                        self._add_finding(
                            vulnerability=f"Credenciales por defecto: {username}:{password}",
                            severity="critical",
                            url=form['url'],
                            payload=f"{username}:{password}",
                            details={
                                "type": "default_credentials",
                                "cvss": 9.8,
                                "cwe": "CWE-798",
                                "owasp": "A07:2021 - Identification and Authentication Failures",
                                "description": f"El formulario de login acepta credenciales por defecto '{username}:{password}'. Esto permite acceso no autorizado al sistema.",
                                "method": form['method'],
                                "username_field": username_field,
                                "password_field": password_field,
                                "username": username,
                                "password": password,
                                "vulnerable": True,
                                "recommendation": "Cambiar inmediatamente todas las credenciales por defecto. Implementar política de contraseñas fuertes, autenticación multifactor y bloqueo de cuentas tras intentos fallidos.",
                                "references": [
                                    "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                                    "https://cwe.mitre.org/data/definitions/798.html"
                                ]
                            }
                        )
                        self.logger.critical(f"[AUTH] Credenciales por defecto funcionan: {username}:{password}")
                        return  # Una credencial exitosa es suficiente
                    
                    time.sleep(1)  # Evitar rate limiting
                    
                except Exception as e:
                    self.logger.debug(f"[AUTH] Error probando credenciales: {e}")

    def _is_login_successful(self, response):
        """Verifica si el login fue exitoso."""
        # Verificar redirección a dashboard/home
        if response.history and any(r.status_code in [301, 302, 303] for r in response.history):
            return True
        
        # Verificar patrones de éxito en el contenido
        response_text = response.text.lower()
        for pattern in self.SUCCESS_PATTERNS:
            if re.search(pattern, response_text):
                return True
        
        # Verificar cookies de sesión
        if 'session' in response.cookies or 'token' in response.cookies:
            return True
        
        return False

    def _check_brute_force_protection(self, login_forms):
        """Verifica protecciones contra fuerza bruta."""
        self.logger.info("[AUTH] Verificando protecciones contra fuerza bruta...")
        
        for form in login_forms[:1]:  # Solo probar el primer formulario
            try:
                # Identificar campos
                username_field = None
                password_field = None
                
                for field_name, field_info in form['fields'].items():
                    field_type = field_info['type']
                    if field_type == 'password':
                        password_field = field_name
                    elif 'user' in field_name.lower() or 'login' in field_name.lower():
                        username_field = field_name
                
                if not (username_field and password_field):
                    continue
                
                # Realizar múltiples intentos fallidos
                attempts = 5
                responses = []
                
                for i in range(attempts):
                    data = {username_field: f"testuser{i}", password_field: f"wrongpass{i}"}
                    response = self._make_request(form['url'], method='POST', data=data)
                    if response:
                        responses.append(response)
                    time.sleep(0.5)
                
                # Verificar si hay rate limiting o bloqueo
                status_codes = [r.status_code for r in responses]
                response_times = [r.elapsed.total_seconds() for r in responses]
                
                # Si todos los intentos tienen el mismo código y tiempo similar, no hay protección
                if len(set(status_codes)) == 1 and max(response_times) - min(response_times) < 1:
                    self._add_finding(
                        vulnerability="Sin protección contra fuerza bruta",
                        severity="medium",
                        url=form['url'],
                        payload=None,
                        details={
                            "type": "no_brute_force_protection",
                            "cvss": 5.3,
                            "cwe": "CWE-307",
                            "owasp": "A07:2021 - Identification and Authentication Failures",
                            "description": f"El formulario de login en '{form['url']}' no implementa protecciones contra ataques de fuerza bruta. No se detectó rate limiting, CAPTCHA o bloqueo de cuenta.",
                            "attempts_tested": attempts,
                            "all_same_response": True,
                            "vulnerable": True,
                            "recommendation": "Implementar rate limiting, CAPTCHA tras intentos fallidos, bloqueo temporal de cuenta, y monitoreo de intentos de login sospechosos.",
                            "references": [
                                "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                            ]
                        }
                    )
                    self.logger.warning("[AUTH] Sin protección contra fuerza bruta detectada")
                
            except Exception as e:
                self.logger.debug(f"[AUTH] Error verificando protección contra fuerza bruta: {e}")

    def _check_insecure_configs(self):
        """Verifica configuraciones inseguras de autenticación."""
        try:
            # Verificar si usa HTTP en lugar de HTTPS
            if self.target_url.startswith('http://'):
                self._add_finding(
                    vulnerability="Autenticación sobre HTTP (sin cifrado)",
                    severity="high",
                    url=self.target_url,
                    payload=None,
                    details={
                        "type": "insecure_transport",
                        "cvss": 7.5,
                        "cwe": "CWE-319",
                        "owasp": "A02:2021 - Cryptographic Failures",
                        "description": "El sitio no usa HTTPS, lo que significa que las credenciales se transmiten sin cifrado y pueden ser interceptadas.",
                        "protocol": "HTTP",
                        "vulnerable": True,
                        "recommendation": "Implementar HTTPS obligatorio con certificado SSL/TLS válido. Redirigir todo el tráfico HTTP a HTTPS.",
                        "references": [
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                        ]
                    }
                )
                self.logger.warning("[AUTH] Sitio usa HTTP sin cifrado")
            
        except Exception as e:
            self.logger.debug(f"[AUTH] Error verificando configuraciones inseguras: {e}")
