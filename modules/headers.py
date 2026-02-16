"""
Módulo de análisis de Security Headers.
Detecta headers de seguridad faltantes o mal configurados según OWASP y mejores prácticas.
"""

import requests
from core.base_module import VulnerabilityModule
from core.logger import get_logger
from datetime import datetime
import json
import os


class HeadersModule(VulnerabilityModule):
    """
    Analiza los headers de seguridad HTTP del objetivo.
    Verifica presencia, configuración correcta y detecta problemas comunes.
    """
    
    # Definición de headers de seguridad críticos y sus configuraciones recomendadas
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "high",
            "description": "Fuerza el uso de HTTPS y previene downgrade attacks",
            "recommendation": "Añadir: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "cvss": 7.5,
            "references": [
                "https://owasp.org/www-project-secure-headers/#strict-transport-security",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
            ],
            "required_values": ["max-age"],
            "recommended_values": ["includeSubDomains", "preload"]
        },
        "X-Frame-Options": {
            "severity": "medium",
            "description": "Previene ataques de clickjacking",
            "recommendation": "Añadir: X-Frame-Options: DENY o SAMEORIGIN",
            "cvss": 6.5,
            "references": [
                "https://owasp.org/www-project-secure-headers/#x-frame-options",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
            ],
            "valid_values": ["DENY", "SAMEORIGIN"]
        },
        "X-Content-Type-Options": {
            "severity": "medium",
            "description": "Previene MIME-sniffing attacks",
            "recommendation": "Añadir: X-Content-Type-Options: nosniff",
            "cvss": 5.3,
            "references": [
                "https://owasp.org/www-project-secure-headers/#x-content-type-options",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
            ],
            "valid_values": ["nosniff"]
        },
        "Content-Security-Policy": {
            "severity": "high",
            "description": "Previene XSS, clickjacking y otros ataques de inyección de código",
            "recommendation": "Implementar una política CSP restrictiva. Ejemplo: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
            "cvss": 7.5,
            "references": [
                "https://owasp.org/www-project-secure-headers/#content-security-policy",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                "https://csp-evaluator.withgoogle.com/"
            ],
            "dangerous_values": ["unsafe-inline", "unsafe-eval", "*"],
            "check_function": "_check_csp_policy"
        },
        "X-XSS-Protection": {
            "severity": "low",
            "description": "Activa el filtro XSS del navegador (deprecado pero útil para navegadores antiguos)",
            "recommendation": "Añadir: X-XSS-Protection: 1; mode=block",
            "cvss": 3.7,
            "references": [
                "https://owasp.org/www-project-secure-headers/#x-xss-protection",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
            ],
            "note": "Deprecado en favor de CSP, pero útil para compatibilidad"
        },
        "Referrer-Policy": {
            "severity": "medium",
            "description": "Controla qué información de referrer se envía en las peticiones",
            "recommendation": "Añadir: Referrer-Policy: strict-origin-when-cross-origin o no-referrer",
            "cvss": 5.3,
            "references": [
                "https://owasp.org/www-project-secure-headers/#referrer-policy",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
            ],
            "recommended_values": ["no-referrer", "strict-origin-when-cross-origin", "strict-origin"]
        },
        "Permissions-Policy": {
            "severity": "medium",
            "description": "Controla qué características del navegador pueden usarse",
            "recommendation": "Añadir: Permissions-Policy: geolocation=(), microphone=(), camera=()",
            "cvss": 5.3,
            "references": [
                "https://owasp.org/www-project-secure-headers/#permissions-policy",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
            ]
        }
    }
    
    # Headers que revelan información sensible
    INFORMATION_DISCLOSURE_HEADERS = {
        "Server": {
            "severity": "low",
            "description": "Revela información sobre el servidor web",
            "recommendation": "Eliminar o ofuscar el header Server",
            "cvss": 3.7
        },
        "X-Powered-By": {
            "severity": "low",
            "description": "Revela información sobre la tecnología backend",
            "recommendation": "Eliminar el header X-Powered-By",
            "cvss": 3.7
        },
        "X-AspNet-Version": {
            "severity": "low",
            "description": "Revela la versión de ASP.NET",
            "recommendation": "Eliminar el header X-AspNet-Version",
            "cvss": 3.7
        },
        "X-AspNetMvc-Version": {
            "severity": "low",
            "description": "Revela la versión de ASP.NET MVC",
            "recommendation": "Eliminar el header X-AspNetMvc-Version",
            "cvss": 3.7
        }
    }

    def __init__(self, config):
        super().__init__(config)
        self.logger = get_logger("headers_module")
        self.target_url = config.get("target_url")
        self.findings = []
        self.headers_response = {}
        self.scan_timestamp = config.get("scan_timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.report_dir = config.get("report_dir", f"reports/scan_{self.scan_timestamp}")

    def scan(self):
        """Ejecuta el análisis completo de security headers."""
        self.logger.info(f"[Headers] Iniciando análisis de security headers en: {self.target_url}")
        
        try:
            # Realizar petición al objetivo
            response = requests.get(
                self.target_url,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) WebSecFramework/1.0"}
            )
            
            self.headers_response = dict(response.headers)
            self.logger.info(f"[Headers] Respuesta recibida (Status: {response.status_code})")
            
            # Análisis de headers de seguridad faltantes o mal configurados
            self._check_missing_headers()
            
            # Análisis de headers que revelan información
            self._check_information_disclosure()
            
            # Análisis de configuraciones inseguras
            self._check_insecure_configurations()
            
            # Exportar resultados
            self._export_results()
            
            # Resumen
            critical = len([f for f in self.findings if f["severity"] == "critical"])
            high = len([f for f in self.findings if f["severity"] == "high"])
            medium = len([f for f in self.findings if f["severity"] == "medium"])
            low = len([f for f in self.findings if f["severity"] == "low"])
            
            self.logger.info(f"[Headers] Análisis completado: {len(self.findings)} hallazgos")
            self.logger.info(f"[Headers] Severidad: Critical={critical}, High={high}, Medium={medium}, Low={low}")
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"[Headers] Error al conectar con {self.target_url}: {e}")
        except Exception as e:
            self.logger.error(f"[Headers] Error inesperado: {e}")

    def _check_missing_headers(self):
        """Verifica headers de seguridad faltantes."""
        for header_name, header_info in self.SECURITY_HEADERS.items():
            header_value = self._get_header_case_insensitive(header_name)
            
            if not header_value:
                # Header faltante
                finding = {
                    "type": "missing_security_header",
                    "severity": header_info["severity"],
                    "header": header_name,
                    "title": f"Security Header Faltante: {header_name}",
                    "description": header_info["description"],
                    "recommendation": header_info["recommendation"],
                    "cvss": header_info["cvss"],
                    "references": header_info["references"],
                    "evidence": {
                        "url": self.target_url,
                        "header_present": False,
                        "current_value": None
                    }
                }
                
                if "note" in header_info:
                    finding["note"] = header_info["note"]
                
                self.findings.append(finding)
                self.logger.warning(f"[Headers] Faltante: {header_name} (Severidad: {header_info['severity']})")
            else:
                # Header presente, verificar configuración
                self._validate_header_configuration(header_name, header_value, header_info)

    def _validate_header_configuration(self, header_name, header_value, header_info):
        """Valida que un header presente esté correctamente configurado."""
        issues = []
        
        # Verificar valores válidos
        if "valid_values" in header_info:
            if not any(valid in header_value.upper() for valid in header_info["valid_values"]):
                issues.append(f"Valor no recomendado. Usar: {', '.join(header_info['valid_values'])}")
        
        # Verificar valores requeridos
        if "required_values" in header_info:
            for required in header_info["required_values"]:
                if required not in header_value.lower():
                    issues.append(f"Falta directiva requerida: {required}")
        
        # Verificar valores peligrosos
        if "dangerous_values" in header_info:
            for dangerous in header_info["dangerous_values"]:
                if dangerous in header_value.lower():
                    issues.append(f"Valor inseguro detectado: {dangerous}")
        
        # Verificación especial para CSP
        if header_name == "Content-Security-Policy":
            csp_issues = self._check_csp_policy(header_value)
            issues.extend(csp_issues)
        
        # Verificación especial para HSTS
        if header_name == "Strict-Transport-Security":
            hsts_issues = self._check_hsts_policy(header_value)
            issues.extend(hsts_issues)
        
        if issues:
            finding = {
                "type": "misconfigured_security_header",
                "severity": "medium",  # Presente pero mal configurado es menos grave
                "header": header_name,
                "title": f"Security Header Mal Configurado: {header_name}",
                "description": f"{header_info['description']}. Problemas detectados: {'; '.join(issues)}",
                "recommendation": header_info["recommendation"],
                "cvss": header_info["cvss"] * 0.7,  # Reducir CVSS si está presente pero mal configurado
                "references": header_info["references"],
                "evidence": {
                    "url": self.target_url,
                    "header_present": True,
                    "current_value": header_value,
                    "issues": issues
                }
            }
            self.findings.append(finding)
            self.logger.warning(f"[Headers] Mal configurado: {header_name} - {'; '.join(issues)}")

    def _check_csp_policy(self, csp_value):
        """Analiza la política CSP en busca de configuraciones inseguras."""
        issues = []
        
        # Verificar uso de 'unsafe-inline'
        if "'unsafe-inline'" in csp_value:
            issues.append("'unsafe-inline' permite ejecución de scripts inline (riesgo XSS)")
        
        # Verificar uso de 'unsafe-eval'
        if "'unsafe-eval'" in csp_value:
            issues.append("'unsafe-eval' permite eval() y similares (riesgo XSS)")
        
        # Verificar wildcards peligrosos
        if " * " in csp_value or csp_value.startswith("*") or csp_value.endswith("*"):
            issues.append("Wildcard '*' permite cualquier origen (política muy permisiva)")
        
        # Verificar data: URIs en script-src
        if "script-src" in csp_value and "data:" in csp_value:
            issues.append("data: URIs en script-src pueden permitir XSS")
        
        # Verificar ausencia de default-src
        if "default-src" not in csp_value:
            issues.append("Falta directiva 'default-src' (fallback recomendado)")
        
        # Verificar object-src
        if "object-src" not in csp_value:
            issues.append("Falta 'object-src' (recomendado: object-src 'none')")
        
        return issues

    def _check_hsts_policy(self, hsts_value):
        """Analiza la política HSTS en busca de configuraciones débiles."""
        issues = []
        
        # Extraer max-age
        import re
        max_age_match = re.search(r'max-age=(\d+)', hsts_value)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # 1 año
                issues.append(f"max-age muy bajo ({max_age}s). Recomendado: 31536000 (1 año)")
        
        # Verificar includeSubDomains
        if "includesubdomains" not in hsts_value.lower():
            issues.append("Falta 'includeSubDomains' (recomendado para proteger subdominios)")
        
        return issues

    def _check_information_disclosure(self):
        """Detecta headers que revelan información sensible."""
        for header_name, header_info in self.INFORMATION_DISCLOSURE_HEADERS.items():
            header_value = self._get_header_case_insensitive(header_name)
            
            if header_value:
                finding = {
                    "type": "information_disclosure",
                    "severity": header_info["severity"],
                    "header": header_name,
                    "title": f"Information Disclosure: {header_name}",
                    "description": header_info["description"],
                    "recommendation": header_info["recommendation"],
                    "cvss": header_info["cvss"],
                    "references": [
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
                    ],
                    "evidence": {
                        "url": self.target_url,
                        "header_present": True,
                        "disclosed_value": header_value
                    }
                }
                self.findings.append(finding)
                self.logger.info(f"[Headers] Information Disclosure: {header_name} = {header_value}")

    def _check_insecure_configurations(self):
        """Detecta configuraciones inseguras adicionales."""
        
        # Verificar Access-Control-Allow-Origin permisivo
        acao = self._get_header_case_insensitive("Access-Control-Allow-Origin")
        if acao == "*":
            finding = {
                "type": "insecure_cors",
                "severity": "medium",
                "header": "Access-Control-Allow-Origin",
                "title": "CORS Permisivo: Access-Control-Allow-Origin: *",
                "description": "El header CORS permite peticiones desde cualquier origen, lo que puede exponer datos sensibles",
                "recommendation": "Restringir Access-Control-Allow-Origin a dominios específicos de confianza",
                "cvss": 5.3,
                "references": [
                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"
                ],
                "evidence": {
                    "url": self.target_url,
                    "current_value": acao
                }
            }
            self.findings.append(finding)
            self.logger.warning("[Headers] CORS permisivo detectado: Access-Control-Allow-Origin: *")
        
        # Verificar X-Frame-Options vs CSP frame-ancestors
        xfo = self._get_header_case_insensitive("X-Frame-Options")
        csp = self._get_header_case_insensitive("Content-Security-Policy")
        
        if xfo and csp and "frame-ancestors" in csp:
            finding = {
                "type": "redundant_headers",
                "severity": "info",
                "header": "X-Frame-Options",
                "title": "Header Redundante: X-Frame-Options",
                "description": "X-Frame-Options es redundante cuando CSP frame-ancestors está presente. CSP tiene prioridad.",
                "recommendation": "Mantener solo CSP frame-ancestors para navegadores modernos, X-Frame-Options para compatibilidad",
                "cvss": 0.0,
                "references": [
                    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors"
                ],
                "evidence": {
                    "url": self.target_url,
                    "xfo_value": xfo,
                    "csp_value": csp
                }
            }
            self.findings.append(finding)

    def _get_header_case_insensitive(self, header_name):
        """Obtiene un header ignorando mayúsculas/minúsculas."""
        for key, value in self.headers_response.items():
            if key.lower() == header_name.lower():
                return value
        return None

    def _export_results(self):
        """Exporta los hallazgos a JSON."""
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            
            output_data = {
                "scan_info": {
                    "target": self.target_url,
                    "timestamp": self.scan_timestamp,
                    "module": "security_headers",
                    "total_findings": len(self.findings)
                },
                "headers_analyzed": self.headers_response,
                "findings": self.findings,
                "summary": {
                    "critical": len([f for f in self.findings if f["severity"] == "critical"]),
                    "high": len([f for f in self.findings if f["severity"] == "high"]),
                    "medium": len([f for f in self.findings if f["severity"] == "medium"]),
                    "low": len([f for f in self.findings if f["severity"] == "low"]),
                    "info": len([f for f in self.findings if f["severity"] == "info"])
                }
            }
            
            output_path = os.path.join(self.report_dir, "headers_findings.json")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"[Headers] Resultados exportados en: {output_path}")
            
        except Exception as e:
            self.logger.error(f"[Headers] Error al exportar resultados: {e}")

    def get_results(self):
        """Devuelve los hallazgos encontrados."""
        return self.findings
