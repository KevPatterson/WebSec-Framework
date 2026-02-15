# Módulo de Security Headers

## Descripción

El módulo de Security Headers analiza los headers HTTP de seguridad de una aplicación web y detecta:

- **Headers faltantes**: Headers de seguridad que deberían estar presentes
- **Headers mal configurados**: Headers presentes pero con valores inseguros
- **Information Disclosure**: Headers que revelan información sensible
- **Configuraciones inseguras**: CORS permisivo, políticas CSP débiles, etc.

## Características

### Headers Analizados

#### Headers de Seguridad Críticos

1. **Strict-Transport-Security (HSTS)**
   - Severidad: HIGH
   - Fuerza el uso de HTTPS
   - Verifica: max-age, includeSubDomains, preload

2. **X-Frame-Options**
   - Severidad: HIGH
   - Previene clickjacking
   - Valores válidos: DENY, SAMEORIGIN

3. **Content-Security-Policy (CSP)**
   - Severidad: HIGH
   - Previene XSS y otros ataques de inyección
   - Detecta: unsafe-inline, unsafe-eval, wildcards peligrosos
   - Verifica: default-src, object-src, script-src

4. **X-Content-Type-Options**
   - Severidad: MEDIUM
   - Previene MIME-sniffing
   - Valor válido: nosniff

5. **Referrer-Policy**
   - Severidad: MEDIUM
   - Controla información de referrer
   - Valores recomendados: no-referrer, strict-origin-when-cross-origin

6. **Permissions-Policy**
   - Severidad: MEDIUM
   - Controla características del navegador
   - Ejemplo: geolocation=(), microphone=(), camera=()

7. **X-XSS-Protection**
   - Severidad: LOW
   - Filtro XSS del navegador (deprecado)
   - Útil para compatibilidad con navegadores antiguos

#### Information Disclosure

Detecta headers que revelan información sensible:
- Server
- X-Powered-By
- X-AspNet-Version
- X-AspNetMvc-Version

#### Configuraciones Inseguras

- **CORS Permisivo**: Access-Control-Allow-Origin: *
- **Headers Redundantes**: X-Frame-Options cuando CSP frame-ancestors está presente

## Uso

### Uso Básico

```python
from modules.headers import HeadersModule
from datetime import datetime

# Configuración
config = {
    "target_url": "https://example.com",
    "scan_timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
    "report_dir": "reports/scan_example"
}

# Crear y ejecutar módulo
headers_module = HeadersModule(config)
headers_module.scan()

# Obtener resultados
findings = headers_module.get_results()
```

### Uso con Scanner

```python
from core.scanner import Scanner
from modules.headers import HeadersModule

# Crear scanner
scanner = Scanner("https://example.com", {})

# Registrar módulo
scanner.register_module(HeadersModule(scanner.config))

# Ejecutar escaneo
scanner.run()
```

### Uso desde CLI

```bash
python run.py https://example.com
```

## Formato de Salida

### JSON Output

El módulo genera un archivo `headers_findings.json` con la siguiente estructura:

```json
{
  "scan_info": {
    "target": "https://example.com",
    "timestamp": "20260215_123456",
    "module": "security_headers",
    "total_findings": 5
  },
  "headers_analyzed": {
    "Server": "nginx",
    "Content-Type": "text/html",
    ...
  },
  "findings": [
    {
      "type": "missing_security_header",
      "severity": "high",
      "header": "Strict-Transport-Security",
      "title": "Security Header Faltante: Strict-Transport-Security",
      "description": "Fuerza el uso de HTTPS y previene downgrade attacks",
      "recommendation": "Añadir: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      "cvss": 7.5,
      "references": [
        "https://owasp.org/www-project-secure-headers/#strict-transport-security"
      ],
      "evidence": {
        "url": "https://example.com",
        "header_present": false,
        "current_value": null
      }
    }
  ],
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 3,
    "low": 1,
    "info": 0
  }
}
```

## Tipos de Hallazgos

### missing_security_header
Header de seguridad completamente ausente.

### misconfigured_security_header
Header presente pero con configuración insegura o incompleta.

### information_disclosure
Header que revela información sensible sobre la infraestructura.

### insecure_cors
Configuración CORS permisiva que puede exponer datos.

### redundant_headers
Headers redundantes que pueden simplificarse.

## Severidades

- **CRITICAL**: Vulnerabilidades críticas (actualmente no aplicable a headers)
- **HIGH**: Headers de seguridad críticos faltantes (HSTS, CSP, X-Frame-Options)
- **MEDIUM**: Headers importantes faltantes o mal configurados
- **LOW**: Information disclosure, headers deprecados
- **INFO**: Recomendaciones, headers redundantes

## CVSS Scoring

Cada hallazgo incluye un score CVSS base:
- Headers críticos faltantes: 6.5 - 7.5
- Headers importantes faltantes: 5.3
- Information disclosure: 3.7
- Headers mal configurados: 70% del score original

## Validaciones Especiales

### Content-Security-Policy (CSP)

Detecta:
- `'unsafe-inline'`: Permite scripts inline (riesgo XSS)
- `'unsafe-eval'`: Permite eval() (riesgo XSS)
- Wildcards `*`: Política muy permisiva
- `data:` URIs en script-src
- Ausencia de `default-src`
- Ausencia de `object-src`

### Strict-Transport-Security (HSTS)

Verifica:
- `max-age` >= 31536000 (1 año)
- Presencia de `includeSubDomains`
- Recomendación de `preload`

## Referencias

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/)
- [Security Headers Scanner](https://securityheaders.com/)

## Ejemplos de Remediación

### Añadir HSTS

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### Añadir CSP Básico

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'
```

### Añadir X-Frame-Options

```
X-Frame-Options: DENY
```

### Añadir X-Content-Type-Options

```
X-Content-Type-Options: nosniff
```

### Eliminar Headers de Information Disclosure

Configurar el servidor web para no enviar:
- Server
- X-Powered-By
- X-AspNet-Version

## Limitaciones

- No valida la efectividad real de los headers (solo su presencia y sintaxis)
- No detecta bypasses específicos de CSP
- No analiza headers en respuestas de recursos estáticos
- No verifica la implementación correcta de HSTS preload

## Próximas Mejoras

- [ ] Análisis de CSP más profundo con CSP Evaluator
- [ ] Detección de bypasses conocidos de CSP
- [ ] Análisis de headers en múltiples endpoints
- [ ] Verificación de HSTS preload list
- [ ] Detección de headers obsoletos adicionales
- [ ] Scoring personalizable por organización
