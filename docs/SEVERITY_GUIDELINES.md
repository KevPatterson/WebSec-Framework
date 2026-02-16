# Guía de Severidades - WebSec Framework

Este documento establece las severidades y scores CVSS para todas las vulnerabilidades detectadas por el framework, siguiendo los estándares OWASP y CVSS v3.1.

## Escala de Severidades

### CRITICAL (9.0-10.0)
Vulnerabilidades que permiten compromiso total del sistema, ejecución remota de código, o acceso completo a datos sensibles.

| Vulnerabilidad | CVSS | Justificación |
|----------------|------|---------------|
| SQL Injection (Error-based) | 9.8 | Permite extracción completa de BD, modificación de datos, potencial RCE |
| Command Injection | 9.8 | Ejecución arbitraria de comandos del SO, compromiso total del servidor |
| Remote File Inclusion (RFI) | 9.1 | Permite ejecución de código remoto arbitrario |
| XXE con lectura de archivos | 9.1 | Lectura de archivos sensibles del sistema (/etc/passwd, win.ini) |
| CORS Credentials + Wildcard | 9.1 | Robo de credenciales y datos sensibles desde cualquier origen |
| CORS Credentials + Reflection | 9.1 | Robo de credenciales desde dominios maliciosos |
| SSRF a Metadata Endpoints | 9.1 | Acceso a credenciales cloud (AWS, GCP), compromiso de infraestructura |
| Credenciales por Defecto | 9.8 | Acceso no autorizado inmediato al sistema |

### HIGH (7.0-8.9)
Vulnerabilidades que permiten acceso no autorizado, robo de datos, o compromiso significativo de la seguridad.

| Vulnerabilidad | CVSS | Justificación |
|----------------|------|---------------|
| SQL Injection (Boolean-based) | 8.6 | Extracción de datos mediante inferencia, más lento pero efectivo |
| XSS Reflected | 7.1 | Robo de sesiones, phishing, ejecución de código en contexto del usuario |
| Local File Inclusion (LFI) | 7.5 | Lectura de archivos locales, potencial escalación a RCE |
| XXE sin lectura confirmada | 7.5 | Procesamiento de entidades externas detectado, potencial SSRF |
| SSRF Interno | 8.6 | Acceso a servicios internos, escaneo de red interna |
| CSRF Missing Token | 8.8 | Falsificación de peticiones, acciones no autorizadas |
| CSRF Missing Origin Validation | 8.1 | Bypass de protecciones CSRF mediante manipulación de headers |
| CSRF Unprotected Endpoint | 8.8 | Endpoints críticos sin protección contra CSRF |
| CSRF SameSite=None sin Secure | 7.5 | Cookies vulnerables a ataques CSRF cross-site |
| CORS Wildcard Origin | 7.5 | Acceso a recursos desde cualquier dominio |
| CORS Null Origin Accepted | 7.5 | Explotable desde iframes sandboxed |
| CORS Arbitrary Reflection | 7.5 | Refleja cualquier origin sin validación |
| HSTS Faltante | 7.5 | Vulnerable a downgrade attacks y MITM |
| CSP Faltante | 7.5 | Sin protección contra XSS y inyección de código |
| Autenticación sobre HTTP | 7.5 | Credenciales transmitidas sin cifrado |

### MEDIUM (4.0-6.9)
Vulnerabilidades que requieren condiciones específicas o tienen impacto limitado.

| Vulnerabilidad | CVSS | Justificación |
|----------------|------|---------------|
| XSS DOM-based | 6.1 | Requiere análisis de JavaScript, impacto similar a XSS pero más difícil de explotar |
| CSRF Missing SameSite | 6.5 | Protección adicional faltante, pero puede haber otras defensas |
| CORS Dangerous Methods | 6.5 | Permite operaciones destructivas pero requiere otros vectores |
| X-Frame-Options Faltante | 6.5 | Vulnerable a clickjacking, requiere ingeniería social |
| X-Content-Type-Options | 5.3 | Previene MIME-sniffing, impacto limitado |
| Referrer-Policy | 5.3 | Fuga de información en URLs, impacto menor |
| Permissions-Policy | 5.3 | Control de features del navegador, impacto limitado |
| Sin Protección Brute Force | 5.3 | Permite ataques de fuerza bruta, requiere tiempo |
| HTTP Basic Auth | 5.3 | Credenciales en Base64, requiere intercepción |
| Headers Mal Configurados | 5.0 | Presente pero con configuración insegura |

### LOW (0.1-3.9)
Vulnerabilidades informativas o con impacto mínimo.

| Vulnerabilidad | CVSS | Justificación |
|----------------|------|---------------|
| X-XSS-Protection Faltante | 3.7 | Header deprecado, CSP es la protección moderna |
| Server Header Disclosure | 3.7 | Information disclosure, facilita fingerprinting |
| X-Powered-By Disclosure | 3.7 | Revela tecnología backend, ayuda a atacantes |
| X-AspNet-Version Disclosure | 3.7 | Revela versión específica de framework |
| Headers Redundantes | 0.0 | Informativo, sin impacto de seguridad |

### INFO (0.0)
Hallazgos informativos sin impacto directo en seguridad.

| Vulnerabilidad | CVSS | Justificación |
|----------------|------|---------------|
| Headers Redundantes | 0.0 | Duplicación de headers, sin impacto de seguridad |
| Configuraciones Recomendadas | 0.0 | Mejores prácticas, no vulnerabilidades |

## Criterios de Asignación

### Factores que Aumentan la Severidad:
- **Explotabilidad**: Fácil de explotar sin autenticación
- **Impacto**: Compromiso de confidencialidad, integridad o disponibilidad
- **Alcance**: Afecta a múltiples usuarios o sistemas
- **Privilegios**: No requiere privilegios especiales
- **Interacción**: No requiere interacción del usuario

### Factores que Reducen la Severidad:
- **Complejidad**: Requiere condiciones específicas o múltiples pasos
- **Autenticación**: Requiere credenciales válidas
- **Interacción**: Requiere acción del usuario (phishing, ingeniería social)
- **Alcance**: Impacto limitado a un usuario o recurso específico
- **Mitigaciones**: Existen controles compensatorios

## Referencias

- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)
- [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- [CWE Severity Scoring](https://cwe.mitre.org/cwss/cwss_v1.0.1.html)
- [NIST CVSS Guidelines](https://nvd.nist.gov/vuln-metrics/cvss)

## Notas de Implementación

1. **Consistencia**: Todas las vulnerabilidades del mismo tipo deben tener la misma severidad base
2. **Contexto**: El score puede ajustarse según el contexto específico del hallazgo
3. **Validación**: El sistema de validación puede ajustar el confidence score, no la severidad
4. **Documentación**: Cada hallazgo debe incluir justificación de la severidad asignada

## Actualización

Este documento debe revisarse cuando:
- Se añaden nuevos tipos de vulnerabilidades
- Cambian los estándares CVSS u OWASP
- Se identifican inconsistencias en la asignación de severidades
- Se recibe feedback de usuarios sobre severidades incorrectas

Última actualización: 2026-02-16
