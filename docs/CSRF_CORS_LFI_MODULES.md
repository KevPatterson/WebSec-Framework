# Módulos de Seguridad: CSRF, CORS y LFI/RFI

## Descripción General

Este documento describe los tres nuevos módulos de detección de vulnerabilidades implementados en el scanner de seguridad.

---

## 1. CSRF Detection Module ⭐⭐⭐

### Descripción
Detecta vulnerabilidades de Cross-Site Request Forgery (CSRF) que permiten a atacantes ejecutar acciones no autorizadas en nombre de usuarios autenticados.

### CVSS Score: 8.8 (High)

### Funcionalidades

#### 1.1 Análisis de Tokens CSRF en Formularios
- Escanea todos los formularios POST en la página
- Detecta ausencia de tokens CSRF
- Identifica nombres comunes de tokens: `csrf`, `csrf_token`, `_csrf`, `authenticity_token`, etc.

#### 1.2 Validación de SameSite Cookies
- Verifica el atributo `SameSite` en cookies de sesión
- Detecta cookies sin `SameSite` (vulnerable a CSRF)
- Identifica configuraciones inseguras: `SameSite=None` sin flag `Secure`

#### 1.3 Verificación de Headers Origin/Referer
- Prueba endpoints con headers `Origin` maliciosos
- Detecta falta de validación de origen
- Verifica endpoints sensibles: `/login`, `/api`, etc.

#### 1.4 Detección de Endpoints sin Protección
- Identifica endpoints sensibles sin protección CSRF
- Prueba rutas comunes: `/api/user/update`, `/password/change`, etc.
- Detecta aceptación de peticiones sin token

### Ejemplo de Uso

```python
from core.scanner import Scanner
from modules.csrf import CSRFModule

config = {
    "target_url": "https://example.com",
    "report_dir": "reports/csrf_scan"
}

scanner = Scanner("https://example.com", config)
scanner.register_module(CSRFModule(config))
scanner.run()
```

### Hallazgos Típicos

```json
{
  "vulnerability": "CSRF - Missing Token",
  "severity": "high",
  "cvss_score": 8.8,
  "url": "https://example.com/login",
  "description": "Formulario sin token CSRF detectado",
  "recommendation": "Implementar tokens CSRF en todos los formularios POST"
}
```

---

## 2. CORS Misconfiguration Module ⭐⭐⭐

### Descripción
Análisis profundo de configuraciones Cross-Origin Resource Sharing (CORS) que pueden exponer recursos sensibles a dominios no autorizados.

### CVSS Score: 7.5 (High)

### Funcionalidades

#### 2.1 Detección de Access-Control-Allow-Origin: *
- Identifica uso de wildcard en ACAO
- Evalúa riesgo de exposición de recursos

#### 2.2 Validación de Credentials con Wildcard
- Detecta combinación peligrosa: `ACAO: *` + `ACAC: true`
- Identifica reflexión de origin con credentials

#### 2.3 Análisis de Métodos Permitidos Peligrosos
- Verifica `Access-Control-Allow-Methods`
- Detecta métodos peligrosos: `PUT`, `DELETE`, `PATCH`, `TRACE`

#### 2.4 Detección de Null Origin Acceptance
- Prueba aceptación de `Origin: null`
- Identifica vulnerabilidad explotable desde iframes sandboxed

#### 2.5 Verificación de Reflexión de Origin Arbitrario
- Prueba múltiples orígenes maliciosos
- Detecta reflexión sin validación

### Ejemplo de Uso

```python
from modules.cors import CORSModule

config = {
    "target_url": "https://api.example.com",
    "report_dir": "reports/cors_scan"
}

cors_module = CORSModule(config)
cors_module.scan()
findings = cors_module.get_results()
```

### Hallazgos Típicos

```json
{
  "vulnerability": "CORS - Origin Reflection with Credentials",
  "severity": "critical",
  "cvss_score": 9.1,
  "url": "https://api.example.com",
  "description": "CORS refleja cualquier origin con credentials habilitados",
  "details": {
    "tested_origin": "https://evil.com",
    "reflected_origin": "https://evil.com",
    "credentials": "true"
  }
}
```

---

## 3. LFI/RFI Detection Module ⭐⭐

### Descripción
Detecta vulnerabilidades de Local File Inclusion (LFI) y Remote File Inclusion (RFI) que permiten leer archivos del sistema o ejecutar código remoto.

### CVSS Score: 
- 9.1 (Critical) para RFI
- 7.5 (High) para LFI

### Funcionalidades

#### 3.1 Detección de Path Traversal
- Prueba payloads: `../`, `../../`, `..\\`, etc.
- Detecta acceso a archivos del sistema
- Identifica `/etc/passwd`, `win.ini`, etc.

#### 3.2 Payloads para Archivos del Sistema
- Linux: `/etc/passwd`, `/etc/shadow`, `/proc/self/environ`
- Windows: `win.ini`, `boot.ini`, `system.ini`
- Logs: `/var/log/apache2/access.log`

#### 3.3 Detección de RFI con URLs Externas
- Prueba inclusión de archivos remotos
- Detecta `allow_url_include` habilitado
- Identifica ejecución remota de código

#### 3.4 Análisis de Parámetros Susceptibles
- Parámetros comunes: `file`, `path`, `page`, `include`, `doc`
- Descubrimiento automático en URLs y enlaces
- Fuzzing de parámetros sospechosos

#### 3.5 Técnicas de Bypass
- Encoding: `%2e%2e%2f`, `%252e%252e%252f`
- Double slashes: `....//....//`
- Null byte: `%00` (PHP < 5.3)
- PHP wrappers: `php://filter`, `data://`, `expect://`

### Ejemplo de Uso

```python
from modules.lfi import LFIModule

config = {
    "target_url": "https://example.com/page.php?file=home",
    "report_dir": "reports/lfi_scan"
}

lfi_module = LFIModule(config)
lfi_module.scan()
findings = lfi_module.get_results()
```

### Hallazgos Típicos

```json
{
  "vulnerability": "LFI - Local File Inclusion",
  "severity": "high",
  "cvss_score": 7.5,
  "url": "https://example.com/page.php?file=../../../etc/passwd",
  "parameter": "file",
  "payload": "../../../etc/passwd",
  "details": {
    "evidence": ["root:x:0:0:root:/root:/bin/bash"]
  }
}
```

---

## Integración con el Scanner

### Uso Completo

```python
from core.scanner import Scanner
from modules.csrf import CSRFModule
from modules.cors import CORSModule
from modules.lfi import LFIModule

# Configuración
config = {
    "target_url": "https://example.com",
    "report_dir": "reports/full_scan",
    "export_pdf": True
}

# Crear scanner
scanner = Scanner("https://example.com", config)

# Registrar todos los módulos
scanner.register_module(CSRFModule(config))
scanner.register_module(CORSModule(config))
scanner.register_module(LFIModule(config))

# Ejecutar escaneo
scanner.run()

# Los resultados se exportan automáticamente a:
# - reports/full_scan/csrf_findings.json
# - reports/full_scan/cors_findings.json
# - reports/full_scan/lfi_findings.json
# - reports/full_scan/vulnerability_scan_consolidated.json
# - reports/full_scan/vulnerability_report.html
# - reports/full_scan/vulnerability_report.pdf (si export_pdf=True)
```

---

## Payloads LFI/RFI

Los payloads están definidos en `payloads/lfi.txt` e incluyen:

### Path Traversal
- `../../../etc/passwd`
- `..\..\windows\win.ini`
- Variantes con múltiples niveles

### Encoding
- URL encoding: `%2e%2e%2f`
- Double encoding: `%252e%252e%252f`

### Bypass Filters
- `....//....//....//etc/passwd`
- `....\/....\/....\/etc/passwd`

### PHP Wrappers
- `php://filter/convert.base64-encode/resource=file`
- `data://text/plain;base64,<payload>`
- `expect://id`

---

## Recomendaciones de Seguridad

### Para CSRF
1. Implementar tokens CSRF en todos los formularios
2. Usar `SameSite=Strict` o `SameSite=Lax` en cookies
3. Validar headers `Origin` y `Referer`
4. Usar frameworks con protección CSRF integrada

### Para CORS
1. Nunca usar `Access-Control-Allow-Origin: *` con credentials
2. Implementar whitelist de dominios permitidos
3. Limitar métodos HTTP permitidos
4. Rechazar `Origin: null`

### Para LFI/RFI
1. Validar y sanitizar todos los inputs de archivo
2. Usar whitelist de archivos permitidos
3. Deshabilitar `allow_url_include` en PHP
4. Implementar path canonicalization
5. Usar chroot o contenedores para aislar archivos

---

## Referencias

### CSRF
- [OWASP CSRF](https://owasp.org/www-community/attacks/csrf)
- [CWE-352](https://cwe.mitre.org/data/definitions/352.html)

### CORS
- [MDN CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [PortSwigger CORS](https://portswigger.net/web-security/cors)

### LFI/RFI
- [OWASP LFI](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [CWE-98](https://cwe.mitre.org/data/definitions/98.html)
