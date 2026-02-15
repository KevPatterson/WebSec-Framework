# Descripción

**WebSec Framework** es una plataforma modular y profesional para el análisis de seguridad en aplicaciones web. Permite automatizar el descubrimiento de vulnerabilidades, el fingerprinting tecnológico y la generación de reportes avanzados, integrando herramientas líderes del sector y facilitando la extensión mediante módulos y payloads personalizados. Su objetivo es ofrecer una solución flexible, potente y fácil de usar tanto para pentesters como para equipos de desarrollo y seguridad.
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
5. Descarga los binarios de Nuclei, sqlmap y ZAP y colócalos en `tools/` o configúralos en el PATH.

## Uso y ejemplos

1. Configura el objetivo en `config/target.yaml`.
2. Ejecuta el framework:
	```bash
	python run.py
	```
3. Los resultados se guardarán en la carpeta `reports/` en formatos HTML, JSON, CSV y YAML.

## Payloads y plantillas

- Los payloads para XSS, SQLi, LFI, etc. están en la carpeta `payloads/` y pueden ser editados o ampliados.
- Las plantillas HTML para reportes están en `templates/` y pueden personalizarse con Jinja2.

## Documentación y desarrollo

- Consulta `docs/DEPENDENCIAS.md` para dependencias técnicas y recomendaciones.
- Consulta `docs/PLAN_DESARROLLO.md` para la hoja de ruta y buenas prácticas de desarrollo.
- Cada módulo y clase está documentado con docstrings para facilitar la extensión.

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

- **XSS**: Reflected, Stored, DOM XSS
- **SQLi**: SQL Injection (usa sqlmap para explotación avanzada)
- **LFI**: Local/Remote File Inclusion
- **CSRF**: Cross-Site Request Forgery
- **CORS**: Configuración insegura de CORS
- **Headers**: Análisis de cabeceras de seguridad
- **Auth**: Autenticación débil o básica

Cada módulo implementa métodos `scan()` y `get_results()`, y puede usar payloads personalizados.

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
templates/              # Plantillas HTML para reportes

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

Estas herramientas están integradas pero no desarrolladas por este proyecto. Consulta sus licencias y documentación oficial para más detalles.

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
