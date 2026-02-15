"""
Módulo de detección de mala configuración CORS.
Análisis profundo de configuraciones Cross-Origin Resource Sharing.
CVSS: 7.5 (High)
"""
from core.base_module import VulnerabilityModule
from core.logger import get_logger
import requests
import os
import json
from urllib.parse import urlparse


class CORSModule(VulnerabilityModule):
    """Módulo para detectar configuraciones inseguras de CORS."""
    
    def __init__(self, config):
        super().__init__(config)
        self.logger = get_logger("cors_module")
        self.findings = []
        self.target_url = config.get("target_url")
        self.report_dir = config.get("report_dir", "reports")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
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
            response = self.session.get(self.target_url, timeout=10)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            
            if acao == '*':
                finding = {
                    "vulnerability": "CORS - Wildcard Origin",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "url": self.target_url,
                    "description": "Access-Control-Allow-Origin configurado con wildcard (*)",
                    "details": {
                        "header": "Access-Control-Allow-Origin: *",
                        "risk": "Permite que cualquier dominio acceda a los recursos"
                    },
                    "recommendation": "Especificar dominios permitidos explícitamente en lugar de usar wildcard. Implementar whitelist de orígenes confiables.",
                    "references": [
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
                        "https://portswigger.net/web-security/cors"
                    ]
                }
                self.findings.append(finding)
                self.logger.warning("CORS wildcard detectado")
        
        except Exception as e:
            self.logger.error(f"Error verificando wildcard origin: {e}")
    
    def _check_credentials_with_wildcard(self):
        """Valida credentials con wildcard."""
        self.logger.info("Verificando credentials con wildcard...")
        
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(self.target_url, headers=headers, timeout=10)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '')
            
            # Wildcard con credentials es una configuración crítica
            if acao == '*' and acac.lower() == 'true':
                finding = {
                    "vulnerability": "CORS - Credentials with Wildcard",
                    "severity": "critical",
                    "cvss_score": 9.1,
                    "url": self.target_url,
                    "description": "CORS permite credentials con wildcard origin (configuración inválida pero peligrosa)",
                    "details": {
                        "acao": acao,
                        "acac": acac,
                        "risk": "Exposición de datos sensibles a cualquier origen"
                    },
                    "recommendation": "NUNCA usar wildcard con credentials. Especificar dominios confiables explícitamente.",
                    "references": [
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS/Errors/CORSNotSupportingCredentials"
                    ]
                }
                self.findings.append(finding)
                self.logger.critical("CORS credentials con wildcard detectado")
            
            # Reflexión de origin con credentials
            elif acao == 'https://evil.com' and acac.lower() == 'true':
                finding = {
                    "vulnerability": "CORS - Origin Reflection with Credentials",
                    "severity": "critical",
                    "cvss_score": 9.1,
                    "url": self.target_url,
                    "description": "CORS refleja cualquier origin con credentials habilitados",
                    "details": {
                        "tested_origin": "https://evil.com",
                        "reflected_origin": acao,
                        "credentials": acac,
                        "risk": "Permite robo de datos sensibles desde dominios maliciosos"
                    },
                    "recommendation": "Implementar whitelist estricta de orígenes. No reflejar el header Origin sin validación.",
                    "references": [
                        "https://portswigger.net/web-security/cors/access-control-allow-credentials"
                    ]
                }
                self.findings.append(finding)
                self.logger.critical("CORS reflexión de origin con credentials")
        
        except Exception as e:
            self.logger.error(f"Error verificando credentials: {e}")
    
    def _check_dangerous_methods(self):
        """Analiza métodos permitidos peligrosos."""
        self.logger.info("Analizando métodos CORS permitidos...")
        
        try:
            headers = {'Origin': 'https://test.com'}
            response = self.session.options(self.target_url, headers=headers, timeout=10)
            
            acam = response.headers.get('Access-Control-Allow-Methods', '')
            
            if acam:
                dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
                found_dangerous = [m for m in dangerous_methods if m in acam.upper()]
                
                if found_dangerous:
                    finding = {
                        "vulnerability": "CORS - Dangerous Methods Allowed",
                        "severity": "medium",
                        "cvss_score": 6.5,
                        "url": self.target_url,
                        "description": f"CORS permite métodos HTTP peligrosos: {', '.join(found_dangerous)}",
                        "details": {
                            "allowed_methods": acam,
                            "dangerous_methods": found_dangerous,
                            "risk": "Permite operaciones destructivas desde otros orígenes"
                        },
                        "recommendation": "Limitar métodos CORS solo a los estrictamente necesarios (GET, POST). Evitar PUT, DELETE en recursos sensibles.",
                        "references": [
                            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods"
                        ]
                    }
                    self.findings.append(finding)
                    self.logger.warning(f"Métodos peligrosos permitidos: {found_dangerous}")
        
        except Exception as e:
            self.logger.error(f"Error analizando métodos: {e}")
    
    def _check_null_origin(self):
        """Detecta aceptación de null origin."""
        self.logger.info("Verificando aceptación de null origin...")
        
        try:
            headers = {'Origin': 'null'}
            response = self.session.get(self.target_url, headers=headers, timeout=10)
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            
            if acao == 'null':
                finding = {
                    "vulnerability": "CORS - Null Origin Accepted",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "url": self.target_url,
                    "description": "CORS acepta origin 'null' (puede ser explotado desde sandboxed iframes)",
                    "details": {
                        "acao": acao,
                        "risk": "Atacantes pueden usar iframes sandboxed para enviar origin null"
                    },
                    "recommendation": "Rechazar explícitamente origin 'null'. Validar que el origin sea un dominio válido.",
                    "references": [
                        "https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack"
                    ]
                }
                self.findings.append(finding)
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
                response = self.session.get(self.target_url, headers=headers, timeout=10)
                
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                
                if acao == origin:
                    finding = {
                        "vulnerability": "CORS - Arbitrary Origin Reflection",
                        "severity": "high",
                        "cvss_score": 7.5,
                        "url": self.target_url,
                        "description": f"CORS refleja origin arbitrario sin validación: {origin}",
                        "details": {
                            "tested_origin": origin,
                            "reflected_origin": acao,
                            "risk": "Cualquier dominio puede acceder a los recursos"
                        },
                        "recommendation": "Implementar whitelist de dominios permitidos. No reflejar el header Origin sin validación estricta.",
                        "references": [
                            "https://portswigger.net/web-security/cors"
                        ]
                    }
                    self.findings.append(finding)
                    self.logger.warning(f"Origin arbitrario reflejado: {origin}")
                    break  # Solo reportar una vez
        
        except Exception as e:
            self.logger.error(f"Error verificando reflexión de origin: {e}")
    
    def _export_results(self):
        """Exporta los resultados a JSON."""
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            output_path = os.path.join(self.report_dir, "cors_findings.json")
            
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(self.findings, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Resultados CORS exportados: {output_path}")
        
        except Exception as e:
            self.logger.error(f"Error exportando resultados CORS: {e}")
    
    def get_results(self):
        """Devuelve los hallazgos encontrados."""
        return self.findings
