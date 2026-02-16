"""
Módulo de detección de autenticación débil.
Detecta problemas de autenticación, credenciales por defecto y configuraciones inseguras.
"""

import requests
import re
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from core.base_module import VulnerabilityModule
from core.logger import get_logger
from datetime import datetime
import json
import os
import base64


class AuthModule(VulnerabilityModule):
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
        self.logger = get_logger("auth_module")
        self.target_url = config.get("target_url")
        self.findings = []
        self.tested_forms = set()
        self.scan_timestamp = config.get("scan_timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.report_dir = config.get("report_dir", f"reports/scan_{self.scan_timestamp}")
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
            
            # 6. Exportar resultados
            self._export_results()
            
            # Resumen
            critical = len([f for f in self.findings if f["severity"] == "critical"])
            high = len([f for f in self.findings if f["severity"] == "high"])
            medium = len([f for f in self.findings if f["severity"] == "medium"])
            
            self.logger.info(f"[AUTH] Escaneo completado: {len(self.findings)} hallazgos")
            self.logger.info(f"[AUTH] Severidad: Critical={critical}, High={high}, Medium={medium}")
            
        except Exception as e:
            self.logger.error(f"[AUTH] Error inesperado: {e}")

    def _check_http_auth(self):
        """Verifica autenticación HTTP Basic/Digest."""
        try:
            response = requests.get(self.target_url, timeout=self.timeout)
            
            # Verificar si requiere autenticación HTTP
            if response.status_code == 401:
                auth_header = response.headers.get('WWW-Authenticate', '')
                
                if 'Basic' in auth_header:
                    finding = {
                        "type": "weak_authentication",
                        "severity": "medium",
                        "title": "Autenticación HTTP Basic detectada",
                        "description": "El sitio utiliza autenticación HTTP Basic, que transmite credenciales en Base64 (fácilmente decodificable). Sin HTTPS, las credenciales se envían en texto plano.",
                        "cvss": 5.3,
                        "cwe": "CWE-319",
                        "owasp": "A07:2021 - Identification and Authentication Failures",
                        "recommendation": "Usar HTTPS obligatorio con autenticación basada en tokens (JWT, OAuth2) o sesiones seguras. Evitar HTTP Basic en producción.",
                        "references": [
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                        ],
                        "evidence": {
                            "url": self.target_url,
                            "auth_type": "HTTP Basic",
                            "header": auth_header,
                            "vulnerable": True
                        }
                    }
                    self.findings.append(finding)
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
                    finding = {
                        "type": "default_credentials",
                        "severity": "critical",
                        "title": f"Credenciales por defecto en HTTP Basic: {username}:{password}",
                        "description": f"El sitio acepta credenciales por defecto '{username}:{password}' en autenticación HTTP Basic. Esto permite acceso no autorizado.",
                        "cvss": 9.8,
                        "cwe": "CWE-798",
                        "owasp": "A07:2021 - Identification and Authentication Failures",
                        "recommendation": "Cambiar inmediatamente todas las credenciales por defecto. Implementar política de contraseñas fuertes y autenticación multifactor.",
                        "references": [
                            "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                            "https://cwe.mitre.org/data/definitions/798.html"
                        ],
                        "evidence": {
                            "url": self.target_url,
                            "username": username,
                            "password": password,
                            "vulnerable": True
                        }
                    }
                    self.findings.append(finding)
                    self.logger.critical(f"[AUTH] Credenciales por defecto funcionan: {username}:{password}")
                    return  # Una credencial exitosa es suficiente
                
                time.sleep(0.5)
                
            except Exception as e:
                self.logger.debug(f"[AUTH] Error probando credenciales HTTP Basic: {e}")

    def _discover_login_forms(self):
        """Descubre formularios de login."""
        login_forms = []
        
        try:
            response = requests.get(self.target_url, timeout=self.timeout)
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
                    resp = requests.get(test_url, timeout=self.timeout)
                    
                    if resp.status_code == 200:
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
                        finding = {
                            "type": "default_credentials",
                            "severity": "critical",
                            "title": f"Credenciales por defecto: {username}:{password}",
                            "description": f"El formulario de login acepta credenciales por defecto '{username}:{password}'. Esto permite acceso no autorizado al sistema.",
                            "cvss": 9.8,
                            "cwe": "CWE-798",
                            "owasp": "A07:2021 - Identification and Authentication Failures",
                            "recommendation": "Cambiar inmediatamente todas las credenciales por defecto. Implementar política de contraseñas fuertes, autenticación multifactor y bloqueo de cuentas tras intentos fallidos.",
                            "references": [
                                "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
                                "https://cwe.mitre.org/data/definitions/798.html"
                            ],
                            "evidence": {
                                "url": form['url'],
                                "method": form['method'],
                                "username_field": username_field,
                                "password_field": password_field,
                                "username": username,
                                "password": password,
                                "vulnerable": True
                            }
                        }
                        self.findings.append(finding)
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
                    response = requests.post(form['url'], data=data, timeout=self.timeout)
                    responses.append(response)
                    time.sleep(0.5)
                
                # Verificar si hay rate limiting o bloqueo
                status_codes = [r.status_code for r in responses]
                response_times = [r.elapsed.total_seconds() for r in responses]
                
                # Si todos los intentos tienen el mismo código y tiempo similar, no hay protección
                if len(set(status_codes)) == 1 and max(response_times) - min(response_times) < 1:
                    finding = {
                        "type": "no_brute_force_protection",
                        "severity": "medium",
                        "title": "Sin protección contra fuerza bruta",
                        "description": f"El formulario de login en '{form['url']}' no implementa protecciones contra ataques de fuerza bruta. No se detectó rate limiting, CAPTCHA o bloqueo de cuenta.",
                        "cvss": 5.3,
                        "cwe": "CWE-307",
                        "owasp": "A07:2021 - Identification and Authentication Failures",
                        "recommendation": "Implementar rate limiting, CAPTCHA tras intentos fallidos, bloqueo temporal de cuenta, y monitoreo de intentos de login sospechosos.",
                        "references": [
                            "https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"
                        ],
                        "evidence": {
                            "url": form['url'],
                            "attempts_tested": attempts,
                            "all_same_response": True,
                            "vulnerable": True
                        }
                    }
                    self.findings.append(finding)
                    self.logger.warning("[AUTH] Sin protección contra fuerza bruta detectada")
                
            except Exception as e:
                self.logger.debug(f"[AUTH] Error verificando protección contra fuerza bruta: {e}")

    def _check_insecure_configs(self):
        """Verifica configuraciones inseguras de autenticación."""
        try:
            response = requests.get(self.target_url, timeout=self.timeout)
            
            # Verificar si usa HTTP en lugar de HTTPS
            if self.target_url.startswith('http://'):
                finding = {
                    "type": "insecure_transport",
                    "severity": "high",
                    "title": "Autenticación sobre HTTP (sin cifrado)",
                    "description": "El sitio no usa HTTPS, lo que significa que las credenciales se transmiten sin cifrado y pueden ser interceptadas.",
                    "cvss": 7.5,
                    "cwe": "CWE-319",
                    "owasp": "A02:2021 - Cryptographic Failures",
                    "recommendation": "Implementar HTTPS obligatorio con certificado SSL/TLS válido. Redirigir todo el tráfico HTTP a HTTPS.",
                    "references": [
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                    ],
                    "evidence": {
                        "url": self.target_url,
                        "protocol": "HTTP",
                        "vulnerable": True
                    }
                }
                self.findings.append(finding)
                self.logger.warning("[AUTH] Sitio usa HTTP sin cifrado")
            
        except Exception as e:
            self.logger.debug(f"[AUTH] Error verificando configuraciones inseguras: {e}")

    def _export_results(self):
        """Exporta los hallazgos a JSON."""
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            
            output_data = {
                "scan_info": {
                    "target": self.target_url,
                    "timestamp": self.scan_timestamp,
                    "module": "authentication",
                    "total_findings": len(self.findings),
                    "tested_forms": len(self.tested_forms)
                },
                "findings": self.findings,
                "summary": {
                    "critical": len([f for f in self.findings if f["severity"] == "critical"]),
                    "high": len([f for f in self.findings if f["severity"] == "high"]),
                    "medium": len([f for f in self.findings if f["severity"] == "medium"]),
                    "low": len([f for f in self.findings if f["severity"] == "low"])
                }
            }
            
            output_path = os.path.join(self.report_dir, "auth_findings.json")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"[AUTH] Resultados exportados en: {output_path}")
            
        except Exception as e:
            self.logger.error(f"[AUTH] Error al exportar resultados: {e}")

    def get_results(self):
        """Devuelve los hallazgos encontrados."""
        return self.findings
