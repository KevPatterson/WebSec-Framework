# WebSec Framework - Guía Rápida

## Instalación Rápida

```bash
# Clonar repositorio
git clone <repo-url>
cd websec-framework

# Instalar dependencias
pip install -r requirements.txt

# (Opcional) Para crawling JS dinámico
pip install playwright
python -m playwright install chromium
```

## Uso Básico

### Escaneo Simple

```bash
python run.py https://example.com
```

Esto ejecutará:
- ✅ Crawling inteligente
- ✅ Fingerprinting tecnológico
- ✅ Análisis de Security Headers, XSS, SQLi
- ✅ Generación de reportes HTML profesionales

### Escaneo con Exportación PDF

```bash
python run.py https://example.com --export-pdf
```

Genera un reporte PDF profesional con TODO el contenido (no solo la pestaña activa).

**Requisitos:**
- Windows: Descarga wkhtmltopdf desde https://wkhtmltopdf.org/downloads.html
- Linux: `sudo apt-get install wkhtmltopdf`
- macOS: `brew install wkhtmltopdf`

### Ver Ayuda Completa

```bash
python run.py --help
```

## Resultados

Los reportes se guardan en `reports/scan_TIMESTAMP/`:

```
reports/scan_20260215_123456/
├── crawl_urls.json                      # URLs descubiertas
├── crawl_forms.json                     # Formularios
├── crawl_js_endpoints.json              # Endpoints JS
├── crawl_tree.json                      # Árbol de navegación
├── fingerprint.json                     # Info tecnológica
├── headers_findings.json                # Hallazgos de security headers
├── xss_findings.json                    # Hallazgos de XSS
├── sqli_findings.json                   # Hallazgos de SQLi
├── vulnerability_scan_consolidated.json # Reporte consolidado JSON
├── vulnerability_report.html            # ⭐ Reporte HTML profesional
└── vulnerability_report.pdf             # ⭐ Reporte PDF (con --export-pdf)
```

## Módulo Security Headers

El módulo implementado analiza:

### ✅ Headers de Seguridad
- Strict-Transport-Security (HSTS)
- Content-Security-Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- X-XSS-Protection

### ✅ Detección de Problemas
- Headers faltantes
- Configuraciones inseguras (CSP con unsafe-inline, HSTS débil)
- Information disclosure (Server, X-Powered-By)
- CORS permisivo

### ✅ Salida Profesional
- CVSS scoring automático
- Referencias a OWASP y MDN
- Recomendaciones de remediación
- Evidencia detallada

## Módulo XSS

Detección de Cross-Site Scripting:

### ✅ Tipos de XSS
- **Reflected XSS**: Inyección en parámetros GET/POST
- **DOM XSS**: Análisis de JavaScript peligroso
- **Stored XSS**: Preparado para futuras mejoras

### ✅ Características
- 60+ payloads de prueba
- Detección de contextos de inyección
- Bypass de filtros comunes
- Análisis de funciones JavaScript peligrosas

### ✅ Técnicas
- Inyección en parámetros y formularios
- Detección de reflejos sin sanitización
- Identificación de eval(), innerHTML, document.write()

## Módulo SQLi

Detección de SQL Injection:

### ✅ Técnicas de Detección
- **Error-based**: Mensajes de error SQL
- **Boolean-based**: Análisis diferencial de respuestas
- **Time-based**: Preparado para futuras mejoras

### ✅ Características
- 100+ payloads organizados
- Soporte multi-DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Integración opcional con SQLMap
- Detección de DBMS específico

### ✅ Tipos de Inyección
- UNION-based
- Authentication bypass
- Stacked queries
- Blind injection

## Ejemplo de Hallazgo

```json
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
```

## Uso Programático

```python
from core.scanner import Scanner
from modules.headers import HeadersModule

# Crear scanner
scanner = Scanner("https://example.com", {})

# Registrar módulo
scanner.register_module(HeadersModule(scanner.config))

# Ejecutar
scanner.run()

# Obtener resultados
findings = scanner.all_findings
for finding in findings:
    print(f"{finding['severity'].upper()}: {finding['title']}")
```

## Integración con Nuclei

```bash
# Escaneo básico
python run.py https://example.com --nuclei

# Filtrar por severidad
python run.py https://example.com --nuclei --nuclei-severity high,critical

# Escaneo masivo
python run.py --nuclei-url-list urls.txt --nuclei --nuclei-threads 10

# Exportar resultados
python run.py https://example.com --nuclei --nuclei-output report.json
```

## Visualización Interactiva

```bash
# Iniciar servidor Flask
python app.py

# Abrir en navegador
# http://localhost:5000/crawl_tree
```

## Próximos Módulos

🚧 En desarrollo:
- LFI/RFI (Local/Remote File Inclusion)
- CSRF (Cross-Site Request Forgery)
- CORS (análisis profundo)
- Auth (autenticación débil)

✅ Implementados:
- Security Headers
- XSS (Reflected, DOM-based)
- SQLi (Error-based, Boolean-based)

## Documentación Completa

- `README.md` - Documentación general
- `docs/HEADERS_MODULE.md` - Módulo Security Headers
- `docs/DEPENDENCIAS.md` - Dependencias técnicas
- `docs/PLAN_DESARROLLO.md` - Hoja de ruta

## Soporte

Para más información:
```bash
python run.py --help
```

## Arquitectura

```
websec-framework/
├── core/              # Motor del framework
│   ├── crawler.py     # Crawling inteligente
│   ├── fingerprint.py # Fingerprinting
│   ├── scanner.py     # Orquestador
│   └── external/      # Nuclei, sqlmap, ZAP
├── modules/           # Módulos de vulnerabilidades
│   └── headers.py     # ✅ Security Headers (implementado)
├── payloads/          # Payloads de prueba
├── reports/           # Resultados generados
└── run.py             # Script principal
```

## Características Profesionales

✅ Arquitectura modular y extensible  
✅ Ejecución concurrente optimizada  
✅ Logging centralizado con colores  
✅ CVSS scoring automático  
✅ Referencias a estándares (OWASP, MDN)  
✅ Exportación multi-formato (JSON, CSV, YAML, HTML)  
✅ Integración con herramientas líderes (Nuclei, sqlmap, ZAP)  
✅ Código limpio y bien documentado  

---

**¡Listo para empezar!** 🚀

```bash
python run.py https://example.com
```


## Módulos de Seguridad Avanzados

### CSRF, CORS y LFI/RFI

Los nuevos módulos detectan vulnerabilidades críticas:

```python
from core.scanner import Scanner
from modules.csrf import CSRFModule
from modules.cors import CORSModule
from modules.lfi import LFIModule

# Configuración
config = {
    "target_url": "https://example.com",
    "report_dir": "reports/security_scan",
    "export_pdf": True
}

# Crear scanner
scanner = Scanner("https://example.com", config)

# Registrar módulos de seguridad
scanner.register_module(CSRFModule(config))
scanner.register_module(CORSModule(config))
scanner.register_module(LFIModule(config))

# Ejecutar escaneo
scanner.run()
```

### Prueba Rápida

```bash
# Ejecutar script de prueba
python test_csrf_cors_lfi.py

# Los resultados se guardan en:
# - reports/test_csrf_cors_lfi_TIMESTAMP/csrf_findings.json
# - reports/test_csrf_cors_lfi_TIMESTAMP/cors_findings.json
# - reports/test_csrf_cors_lfi_TIMESTAMP/lfi_findings.json
# - reports/test_csrf_cors_lfi_TIMESTAMP/vulnerability_scan_consolidated.json
```

### Documentación Completa

Para más detalles sobre estos módulos, consulta:
- [docs/CSRF_CORS_LFI_MODULES.md](docs/CSRF_CORS_LFI_MODULES.md)
