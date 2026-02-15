# WebSec Framework (Mini Acunetix)

**WebSec Framework** es una plataforma modular y profesional para el análisis de seguridad en aplicaciones web. Permite automatizar el descubrimiento de vulnerabilidades, el fingerprinting tecnológico y la generación de reportes avanzados, integrando herramientas líderes del sector y facilitando la extensión mediante módulos y payloads personalizados. Su objetivo es ofrecer una solución flexible, potente y fácil de usar tanto para pentesters como para equipos de desarrollo y seguridad.

## 🚀 Inicio Rápido

```bash
# Instalar dependencias
pip install -r requirements.txt

# Ejecutar escaneo
python run.py https://example.com

# Ver ayuda completa
python run.py --help
```

📖 **[Ver Guía Rápida Completa](QUICKSTART.md)**

## 📋 Tabla de Contenidos

- [Características principales](#características-principales)
- [Instalación](#instalación)
- [Uso y ejemplos](#uso-y-ejemplos)
- [Módulos de vulnerabilidad](#módulos-de-vulnerabilidad)
- [Estructura y componentes](#estructura-y-componentes)
- [Flujo de trabajo](#flujo-de-trabajo)
- [Integración con herramientas externas](#integración-con-herramientas-externas)
- [Documentación](#documentación)
- [Cambios recientes](#cambios-recientes)
- [Licencia](#licencia)
## Instalación

```bash
# 1. Clonar repositorio
git clone <repo-url>
cd websec-framework

# 2. Instalar dependencias principales
pip install -r requirements.txt

# 3. (Opcional) Para crawling JS dinámico
pip install playwright
python -m playwright install chromium

# 4. (Opcional) Para exportar en YAML
pip install pyyaml
```

**Nota:** Los binarios de Nuclei, sqlmap y ZAP deben descargarse manualmente y ubicarse en `tools/` o estar en el PATH del sistema.

## Uso y ejemplos

### Uso Básico

```bash
# Escaneo completo de un objetivo
python run.py https://example.com

# Ver ayuda completa
python run.py --help
```

### Escaneo con Nuclei

```bash
# Escaneo básico con Nuclei
python run.py https://example.com --nuclei

# Filtrar por severidad
python run.py https://example.com --nuclei --nuclei-severity high,critical

# Filtrar por tags
python run.py https://example.com --nuclei --nuclei-tags xss,sqli

# Escaneo masivo desde archivo
python run.py --nuclei-url-list urls.txt --nuclei --nuclei-threads 10

# Exportar resultados
python run.py https://example.com --nuclei --nuclei-output report.json --nuclei-output-format json
```

### Uso Programático

```python
from core.scanner import Scanner
from modules.headers import HeadersModule

# Crear scanner
scanner = Scanner("https://example.com", {})

# Registrar módulos
scanner.register_module(HeadersModule(scanner.config))

# Ejecutar escaneo
scanner.run()

# Obtener resultados
findings = scanner.all_findings
```

### Estructura de Reportes

Los resultados se guardan en `reports/scan_TIMESTAMP/`:
- `crawl_urls.json` - URLs descubiertas
- `crawl_forms.json` - Formularios encontrados
- `crawl_js_endpoints.json` - Endpoints JS
- `crawl_tree.json` - Árbol de navegación
- `fingerprint.json` - Información tecnológica
- `headers_findings.json` - Hallazgos de security headers
- `vulnerability_scan_consolidated.json` - Reporte consolidado

### Visualización Interactiva

Para visualizar el árbol de crawling:
1. Ejecuta el crawling normalmente
2. Inicia el servidor Flask: `python app.py`
3. Abre http://localhost:5000/crawl_tree en tu navegador
4. El árbol se muestra con nodos expandibles, tooltips y estética moderna
## Visualización interactiva del árbol de crawling

El archivo `templates/crawl_tree.html` permite visualizar el mapa del sitio descubierto de forma interactiva y profesional:
- Nodos expandibles/colapsables.
- Tooltips para URLs largas.
- Ctrl+Click para abrir URLs.
- Estética moderna (degradados, sombra, responsive).
- Automatización vía Flask.

Para usarlo:
1. Ejecuta el crawling.
2. Inicia el servidor Flask.
3. Accede a la página de visualización.

## Payloads y plantillas

- Los payloads para XSS, SQLi, LFI, etc. están en la carpeta `payloads/` y pueden ser editados o ampliados.
- Las plantillas HTML para reportes están en `templates/` y pueden personalizarse con Jinja2.

## Documentación

### Documentación Principal
- **[README.md](README.md)** - Este archivo, documentación general del framework
- **[QUICKSTART.md](QUICKSTART.md)** - Guía rápida de inicio
- **[docs/HEADERS_MODULE.md](docs/HEADERS_MODULE.md)** - Documentación completa del módulo Security Headers
- **[docs/DEPENDENCIAS.md](docs/DEPENDENCIAS.md)** - Dependencias técnicas y recomendaciones
- **[docs/PLAN_DESARROLLO.md](docs/PLAN_DESARROLLO.md)** - Hoja de ruta y buenas prácticas de desarrollo

### Ayuda en Línea
```bash
python run.py --help
```

### Ejemplos de Código
- **[example_usage.py](example_usage.py)** - Ejemplo de uso integrado del framework
- **[test_headers.py](test_headers.py)** - Script de prueba del módulo Security Headers

## Herramientas externas utilizadas

- [Nuclei](https://github.com/projectdiscovery/nuclei) (ProjectDiscovery)
- [OWASP ZAP](https://www.zaproxy.org/)
- [sqlmap](https://sqlmap.org/)
- [Playwright](https://playwright.dev/python/) (para crawling JS)
- [PyYAML](https://pyyaml.org/) (opcional para exportar YAML)
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)
- [Requests](https://docs.python-requests.org/)
- [Jinja2](https://jinja.palletsprojects.com/)
- [colorlog](https://github.com/borntyping/python-colorlog)

Estas herramientas están integradas pero no desarrolladas por este proyecto. Consulta sus licencias y documentación oficial para más detalles.
## Módulos de vulnerabilidad

Cada módulo es autocontenible y puede activarse/desactivarse vía configuración. Los módulos incluidos son:

### ✅ Módulos Implementados

#### **Security Headers** (COMPLETO)
Análisis profesional de headers de seguridad HTTP según estándares OWASP.

**Características:**
- Detecta headers faltantes: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Valida configuraciones inseguras: CSP con unsafe-inline/unsafe-eval, HSTS con max-age bajo
- Detecta information disclosure: Server, X-Powered-By, X-AspNet-Version
- Identifica CORS permisivo y headers redundantes
- CVSS scoring automático por hallazgo
- Referencias a OWASP y MDN para cada issue

**Severidades detectadas:**
- HIGH: Headers críticos faltantes (HSTS, CSP, X-Frame-Options)
- MEDIUM: Headers importantes faltantes o mal configurados
- LOW: Information disclosure
- INFO: Headers redundantes, recomendaciones

**Salida:**
- `headers_findings.json`: Hallazgos detallados con evidencia
- Recomendaciones de remediación específicas
- Referencias a documentación oficial

**Documentación completa:** [docs/HEADERS_MODULE.md](docs/HEADERS_MODULE.md)

**Ejemplo de uso:**
```bash
python run.py https://example.com
```

**Ejemplo programático:**
```python
from core.scanner import Scanner
from modules.headers import HeadersModule

scanner = Scanner("https://example.com", {})
scanner.register_module(HeadersModule(scanner.config))
scanner.run()
```

### 🚧 Módulos en Desarrollo

- **XSS**: Reflected, Stored, DOM XSS (próximamente)
- **SQLi**: SQL Injection con integración sqlmap (próximamente)
- **LFI**: Local/Remote File Inclusion (próximamente)
- **CSRF**: Cross-Site Request Forgery (próximamente)
- **CORS**: Análisis profundo de CORS (próximamente)
- **Auth**: Autenticación débil o básica (próximamente)

Cada módulo implementa la interfaz `VulnerabilityModule` con métodos `scan()` y `get_results()`, y puede usar payloads personalizados.

## Integración con herramientas externas

El framework integra y orquesta herramientas líderes:
- **Nuclei**: Para escaneo basado en templates y detección rápida de vulnerabilidades conocidas.
- **sqlmap**: Para explotación y detección avanzada de SQLi.
- **OWASP ZAP**: Para escaneo automatizado y pruebas de fuzzing.

> **Nota:** Los binarios de estas herramientas deben descargarse manualmente y ubicarse en la carpeta `tools/` o estar en el PATH del sistema.

## Configuración y personalización

- Edita `config/target.yaml` para definir el objetivo, cabeceras, cookies y parámetros de crawling.
- Puedes crear múltiples archivos YAML para distintos objetivos.
- Los módulos y payloads pueden activarse/desactivarse y personalizarse fácilmente.

# WebSec Framework (Mini Acunetix)

WebSec Framework es una plataforma profesional y extensible para el análisis de seguridad web, inspirada en Acunetix, que automatiza el descubrimiento de vulnerabilidades, el fingerprinting tecnológico y la generación de reportes avanzados. Está diseñada para ser modular, fácil de extender y compatible con herramientas líderes del sector.

---

## Tabla de contenidos
- [Características principales](#características-principales)
- [Estructura y componentes](#estructura-y-componentes)
- [Flujo de trabajo](#flujo-de-trabajo)

---

## Características principales
- Crawling inteligente de URLs, formularios y recursos (robots.txt, sitemap.xml, manifest.json, service workers)
- Soporte para crawling dinámico con Playwright (JS)
- Fingerprinting tecnológico: servidor, frameworks, cookies, WAF
- Detección de vulnerabilidades comunes: XSS, SQLi, LFI, CSRF, CORS, Headers, Auth
- Validación de falsos positivos
- Integración con Nuclei, sqlmap y OWASP ZAP
- Exportación de resultados en JSON, CSV, YAML y HTML profesional
- Plantillas de reporte personalizables (Jinja2)
- Logging centralizado y colorido
- Modularidad total: fácil de extender con nuevos módulos y payloads

## Estructura y componentes

```
requirements.txt         # Dependencias Python
run.py                  # Script principal de ejecución
config/                 # Configuración de objetivos (YAML)
core/                   # Lógica principal y orquestación
	├─ base_module.py     # Interfaz base para módulos
	├─ crawler.py         # Crawling inteligente
	├─ fingerprint.py     # Fingerprinting tecnológico
	├─ scanner.py         # Orquestador de módulos
	├─ validator.py       # Validación de falsos positivos
	├─ reporter.py        # Generación de reportes
	├─ logger.py          # Logger centralizado
	└─ external/          # Integración con Nuclei, sqlmap, ZAP
modules/                # Módulos de vulnerabilidad (XSS, SQLi, LFI, etc.)
payloads/               # Payloads para pruebas de inyección
reports/                # Resultados y reportes generados
templates/              # Plantillas HTML para reportes y visualización interactiva

tools/                  # Binarios y recursos externos (Nuclei, sqlmap, ZAP, etc.)
docs/                   # Documentación técnica y plan de desarrollo
```

### Descripción de carpetas clave
- **core/**: Motor del framework. Incluye crawling, fingerprinting, orquestación de módulos, validación y reportería.
- **modules/**: Cada archivo implementa un módulo de detección de vulnerabilidad (XSS, SQLi, LFI, CSRF, CORS, Headers, Auth). Todos heredan de una interfaz base.
- **core/external/**: Integración robusta con Nuclei, sqlmap y ZAP (ejecución, parseo de resultados, manejo de errores).
- **payloads/**: Listas de payloads para pruebas automáticas (XSS, SQLi, LFI, etc.).
- **templates/**: Plantillas Jinja2 para reportes HTML profesionales.
- **config/**: Archivos YAML para definir objetivos, cabeceras, cookies y parámetros de escaneo.
- **tools/**: Binarios y recursos de herramientas externas (no incluidos, deben descargarse manualmente).
- **docs/**: Documentación técnica, dependencias y plan de desarrollo.

## Flujo de trabajo

1. **Configuración**: Define el objetivo y parámetros en `config/target.yaml`.
2. **Crawling**: Descubre URLs, formularios y recursos usando crawling inteligente (con o sin JS).
3. **Fingerprinting**: Identifica tecnologías, frameworks, cookies y posibles WAF.
4. **Escaneo de vulnerabilidades**: Cada módulo analiza el objetivo para su vulnerabilidad específica.
5. **Validación**: Se filtran falsos positivos mediante heurísticas y comparación de respuestas.
6. **Reporte**: Se genera un reporte profesional en HTML, JSON, CSV y YAML.

## Instalación

1. Clona el repositorio y entra al directorio del proyecto.
2. Instala las dependencias de Python:

```bash
pip install -r requirements.txt
```

3. (Opcional) Para crawling JS, instala Playwright y Chromium:

```bash
pip install playwright
python -m playwright install chromium
```

4. (Opcional) Instala PyYAML para exportar en YAML:

```bash
pip install pyyaml
```

## Uso

Ejecuta el framework con:

```bash
python run.py
```

Configura el objetivo y parámetros en `config/target.yaml`.

## Herramientas externas utilizadas

- [Nuclei](https://github.com/projectdiscovery/nuclei) (ProjectDiscovery)
- [OWASP ZAP](https://www.zaproxy.org/)
- [sqlmap](https://sqlmap.org/)
- [Playwright](https://playwright.dev/python/) (para crawling JS)
- [PyYAML](https://pyyaml.org/) (opcional para exportar YAML)
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/)
- [Requests](https://docs.python-requests.org/)


## Cambios recientes

### v0.2.0 (Febrero 2026)
- ✅ **Módulo Security Headers completo**: Análisis profesional de headers HTTP según OWASP
  - Detección de 7 headers de seguridad críticos
  - Validación de CSP y HSTS con análisis profundo
  - Information disclosure detection
  - CVSS scoring automático
  - Exportación JSON estructurada
- ✅ **Scanner mejorado**: Consolidación de reportes y ejecución concurrente
- ✅ **Documentación completa**: docs/HEADERS_MODULE.md con ejemplos y referencias

### v0.1.0 (Enero 2026)
- Añadida visualización interactiva del árbol de crawling (`crawl_tree.html`)
- Mejorada la estética general de la visualización (CSS, SVG, responsive)
- Automatización del flujo de crawling y visualización
- Integración completa con Nuclei
- Crawling inteligente con soporte JS (Playwright)

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

## Características principales

- Crawling inteligente de URLs, formularios y recursos (robots.txt, sitemap.xml, manifest.json, service workers)
- Soporte para crawling dinámico con Playwright (JS)
- Fingerprinting tecnológico: servidor, frameworks, cookies, WAF
- Detección de vulnerabilidades: Security Headers (implementado), XSS, SQLi, LFI, CSRF, CORS, Auth (próximamente)
- Validación de falsos positivos
- Integración con Nuclei, sqlmap y OWASP ZAP
- Exportación de resultados en JSON, CSV, YAML y HTML profesional
- Plantillas de reporte personalizables (Jinja2)
- Logging centralizado y colorido
- Modularidad total: fácil de extender con nuevos módulos y payloads
- Ejecución concurrente optimizada

## Estructura y componentes

```
websec-framework/
├── config/                 # Configuración de objetivos (YAML)
├── core/                   # Lógica principal y orquestación
│   ├── base_module.py      # Interfaz base para módulos
│   ├── crawler.py          # Crawling inteligente
│   ├── fingerprint.py      # Fingerprinting tecnológico
│   ├── scanner.py          # Orquestador de módulos
│   ├── validator.py        # Validación de falsos positivos
│   ├── reporter.py         # Generación de reportes
│   ├── logger.py           # Logger centralizado
│   └── external/           # Integración con Nuclei, sqlmap, ZAP
├── modules/                # Módulos de vulnerabilidad
│   ├── headers.py          # ✅ Security Headers (implementado)
│   ├── xss.py              # 🚧 XSS (próximamente)
│   ├── sqli.py             # 🚧 SQLi (próximamente)
│   └── ...                 # Otros módulos
├── payloads/               # Payloads para pruebas de inyección
├── reports/                # Resultados y reportes generados
├── templates/              # Plantillas HTML para reportes
├── tools/                  # Binarios externos (Nuclei, sqlmap, ZAP)
├── docs/                   # Documentación técnica
├── run.py                  # Script principal de ejecución
├── app.py                  # Servidor Flask para visualización
└── requirements.txt        # Dependencias Python
```

### Descripción de carpetas clave

- **core/**: Motor del framework. Incluye crawling, fingerprinting, orquestación de módulos, validación y reportería.
- **modules/**: Cada archivo implementa un módulo de detección de vulnerabilidad. Todos heredan de `VulnerabilityModule`.
- **core/external/**: Integración robusta con Nuclei, sqlmap y ZAP (ejecución, parseo de resultados, manejo de errores).
- **payloads/**: Listas de payloads para pruebas automáticas (XSS, SQLi, LFI, etc.).
- **templates/**: Plantillas Jinja2 para reportes HTML profesionales.
- **config/**: Archivos YAML para definir objetivos, cabeceras, cookies y parámetros de escaneo.
- **tools/**: Binarios y recursos de herramientas externas (no incluidos, deben descargarse manualmente).
- **docs/**: Documentación técnica, dependencias y plan de desarrollo.

## Flujo de trabajo

1. **Configuración**: Define el objetivo y parámetros (puede ser vía CLI o config YAML)
2. **Crawling**: Descubre URLs, formularios y recursos usando crawling inteligente (con o sin JS)
3. **Fingerprinting**: Identifica tecnologías, frameworks, cookies y posibles WAF
4. **Escaneo de vulnerabilidades**: Ejecución concurrente de todos los módulos registrados
5. **Validación**: Se filtran falsos positivos mediante heurísticas y comparación de respuestas
6. **Reporte**: Se genera un reporte profesional consolidado en múltiples formatos

## Cambios recientes

### v0.2.0 (Febrero 2026)
- ✅ **Módulo Security Headers completo**: Análisis profesional de headers HTTP según OWASP
  - Detección de 7 headers de seguridad críticos
  - Validación de CSP y HSTS con análisis profundo
  - Information disclosure detection
  - CVSS scoring automático
  - Exportación JSON estructurada
- ✅ **Scanner mejorado**: Consolidación de reportes y ejecución concurrente
- ✅ **Documentación completa**: docs/HEADERS_MODULE.md con ejemplos y referencias
- ✅ **Guía rápida**: QUICKSTART.md para inicio rápido
- ✅ **Help mejorado**: --help con formato profesional y completo

### v0.1.0 (Enero 2026)
- Añadida visualización interactiva del árbol de crawling (`crawl_tree.html`)
- Mejorada la estética general de la visualización (CSS, SVG, responsive)
- Automatización del flujo de crawling y visualización
- Integración completa con Nuclei
- Crawling inteligente con soporte JS (Playwright)

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---

**Desarrollado con ❤️ para la comunidad de seguridad web**
