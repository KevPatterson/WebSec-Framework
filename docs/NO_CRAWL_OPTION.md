# Opción --no-crawl

## Descripción

La opción `--no-crawl` permite ejecutar el framework WebSec sin realizar el crawling inicial ni el fingerprinting tecnológico. Esto es útil cuando:

- Solo necesitas escanear vulnerabilidades en una URL específica
- Ya conoces la estructura del sitio y no necesitas descubrimiento
- Quieres un escaneo más rápido enfocado solo en vulnerabilidades
- Estás probando un endpoint específico

---

## Uso

### Sintaxis Básica

```bash
python run.py <target> --no-crawl
```

### Ejemplos

#### Escaneo rápido sin crawling
```bash
python run.py https://example.com --no-crawl
```

#### Escaneo sin crawling y sin validación (más rápido)
```bash
python run.py https://example.com --no-crawl --no-validation
```

#### Escaneo sin crawling con exportación a PDF
```bash
python run.py https://example.com --no-crawl --export-pdf
```

#### Escaneo sin crawling filtrando baja confianza
```bash
python run.py https://example.com --no-crawl --filter-low-confidence
```

---

## Comportamiento

### Con --no-crawl

Cuando se usa `--no-crawl`, el framework:

✅ **Ejecuta:**
- Escaneo de vulnerabilidades (10 módulos)
- Sistema de validación (si está habilitado)
- Generación de reportes HTML/PDF
- Exportación de hallazgos en JSON

❌ **NO Ejecuta:**
- Crawling de URLs
- Descubrimiento de formularios
- Análisis de endpoints JavaScript
- Fingerprinting tecnológico
- Generación de árbol de navegación

### Sin --no-crawl (comportamiento por defecto)

El framework ejecuta todo:
- ✅ Crawling completo
- ✅ Fingerprinting
- ✅ Escaneo de vulnerabilidades
- ✅ Validación
- ✅ Reportes

---

## Archivos Generados

### Con --no-crawl

El directorio `reports/scan_TIMESTAMP/` contendrá:

```
reports/scan_20260216_120000/
├── xss_findings.json
├── sqli_findings.json
├── headers_findings.json
├── csrf_findings.json
├── cors_findings.json
├── lfi_findings.json
├── xxe_findings.json
├── ssrf_findings.json
├── cmdi_findings.json
├── auth_findings.json
├── vulnerability_scan_consolidated.json
└── vulnerability_report.html
```

**NO se generan:**
- `crawl_urls.json`
- `crawl_forms.json`
- `crawl_js_endpoints.json`
- `crawl_tree.json`
- `fingerprint.json`

### Sin --no-crawl

Se generan todos los archivos anteriores más:
- `crawl_urls.json`
- `crawl_forms.json`
- `crawl_js_endpoints.json`
- `crawl_tree.json`
- `fingerprint.json`

---

## Ventajas y Desventajas

### Ventajas de usar --no-crawl

✅ **Más rápido:** Reduce el tiempo de escaneo significativamente
✅ **Enfocado:** Solo escanea vulnerabilidades en la URL objetivo
✅ **Menos ruido:** No genera archivos de crawling innecesarios
✅ **Ideal para APIs:** Perfecto para escanear endpoints específicos
✅ **Menos tráfico:** Genera menos peticiones HTTP

### Desventajas de usar --no-crawl

❌ **Menos cobertura:** No descubre URLs adicionales
❌ **Sin contexto:** No obtiene información tecnológica del sitio
❌ **Formularios limitados:** Solo analiza formularios en la URL objetivo
❌ **Sin árbol de navegación:** No genera visualización de estructura

---

## Casos de Uso

### 1. Escaneo de API Endpoint

```bash
# Escanear un endpoint específico de API
python run.py https://api.example.com/v1/users --no-crawl
```

### 2. Prueba Rápida

```bash
# Prueba rápida de vulnerabilidades sin crawling
python run.py https://example.com/login --no-crawl --no-validation
```

### 3. Escaneo de Página Específica

```bash
# Escanear solo una página sin descubrir otras
python run.py https://example.com/admin --no-crawl
```

### 4. Integración en CI/CD

```bash
# Escaneo rápido en pipeline de CI/CD
python run.py $TARGET_URL --no-crawl --filter-low-confidence
```

---

## Comparación de Tiempos

Tiempos aproximados de escaneo en testphp.vulnweb.com:

| Modo | Tiempo Aproximado | Archivos Generados |
|------|-------------------|-------------------|
| **Completo** (sin --no-crawl) | 3-5 minutos | 17 archivos |
| **Sin crawling** (--no-crawl) | 1-2 minutos | 12 archivos |
| **Rápido** (--no-crawl --no-validation) | 30-60 segundos | 12 archivos |

---

## Módulos Ejecutados

Con o sin `--no-crawl`, siempre se ejecutan los **10 módulos de vulnerabilidad**:

1. ✅ XSS - Cross-Site Scripting
2. ✅ SQLi - SQL Injection
3. ✅ Security Headers
4. ✅ CSRF - Cross-Site Request Forgery
5. ✅ CORS - Cross-Origin Resource Sharing
6. ✅ LFI/RFI - File Inclusion
7. ✅ XXE - XML External Entity
8. ✅ SSRF - Server-Side Request Forgery
9. ✅ Command Injection
10. ✅ Authentication

---

## Pruebas

### Ejecutar Test

```bash
python tests/test_no_crawl.py
```

Este test verifica que:
- El escaneo se ejecuta sin crawling
- No se generan archivos de crawling
- Se generan todos los archivos de vulnerabilidades
- El mensaje de "Crawling deshabilitado" aparece

---

## Notas Técnicas

### Implementación

La opción `--no-crawl` modifica el flujo de ejecución en `run.py`:

```python
# Determinar qué tareas ejecutar según las opciones
tasks = []

if not args.no_crawl:
    tasks.append(run_crawler)
    tasks.append(run_finger)
else:
    print("[!] Crawling deshabilitado (--no-crawl). Solo se ejecutará el escaneo de vulnerabilidades.")

tasks.append(run_scanner)
```

### Ejecución Concurrente

- **Con crawling:** 3 tareas concurrentes (crawler, fingerprinter, scanner)
- **Sin crawling:** 1 tarea (solo scanner)

---

## Recomendaciones

### Cuándo usar --no-crawl

✅ Escaneo de endpoints específicos de API
✅ Pruebas rápidas de vulnerabilidades
✅ Cuando ya conoces la estructura del sitio
✅ Integración en pipelines de CI/CD
✅ Escaneo de páginas individuales

### Cuándo NO usar --no-crawl

❌ Primera vez escaneando un sitio
❌ Necesitas descubrir todas las URLs
❌ Quieres un análisis completo
❌ Necesitas el árbol de navegación
❌ Requieres información tecnológica del sitio

---

## Referencias

- **README.md** - Documentación principal
- **QUICKSTART.md** - Guía rápida
- **run.py** - Implementación de la opción
- **tests/test_no_crawl.py** - Test de la funcionalidad

---

**Versión:** 0.7.0  
**Fecha:** 16 de febrero de 2026  
**Estado:** ✅ IMPLEMENTADO
