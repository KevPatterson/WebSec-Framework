# Estructura de Reportes

Los reportes del framework se organizan en carpetas individuales por cada escaneo realizado.

## Formato de Carpetas

Cada escaneo genera una carpeta con el formato: `scan_YYYYMMDD_HHMMSS`

Ejemplo: `scan_20240315_143022` (escaneo realizado el 15 de marzo de 2024 a las 14:30:22)

## Contenido de cada Carpeta de Escaneo

Cada carpeta de escaneo contiene los siguientes archivos:

### Crawling
- `crawl_urls.json` - Lista de URLs descubiertas (formato JSON)
- `crawl_urls.csv` - Lista de URLs descubiertas (formato CSV)
- `crawl_urls.yaml` - Lista de URLs descubiertas (formato YAML, si pyyaml está instalado)
- `crawl_forms.json` - Formularios encontrados con sus campos
- `crawl_forms.yaml` - Formularios encontrados (formato YAML)
- `crawl_js_endpoints.json` - Endpoints descubiertos en código JavaScript
- `crawl_js_endpoints.csv` - Endpoints JS (formato CSV)
- `crawl_js_endpoints.yaml` - Endpoints JS (formato YAML)
- `crawl_tree.json` - Árbol de navegación del sitio

### Fingerprinting
- `fingerprint.json` - Información tecnológica del objetivo (servidor, frameworks, WAF, headers, cookies)

### Vulnerabilidades
- `vulnerability_report.html` - Reporte visual de vulnerabilidades encontradas
- `vulnerability_report.json` - Reporte de vulnerabilidades en formato JSON

## Ventajas de esta Estructura

1. **Organización**: Cada escaneo está completamente aislado en su propia carpeta
2. **Trazabilidad**: El timestamp en el nombre permite identificar cuándo se realizó cada escaneo
3. **Comparación**: Facilita comparar resultados entre diferentes escaneos
4. **Limpieza**: Es fácil eliminar escaneos antiguos sin afectar los recientes
5. **Visualización**: Todos los archivos relacionados están juntos para análisis completo

## Ejemplo de Estructura

```
reports/
├── README.md
├── scan_20240315_143022/
│   ├── crawl_urls.json
│   ├── crawl_urls.csv
│   ├── crawl_urls.yaml
│   ├── crawl_forms.json
│   ├── crawl_forms.yaml
│   ├── crawl_js_endpoints.json
│   ├── crawl_js_endpoints.csv
│   ├── crawl_js_endpoints.yaml
│   ├── crawl_tree.json
│   ├── fingerprint.json
│   ├── vulnerability_report.html
│   └── vulnerability_report.json
└── scan_20240316_091545/
    ├── crawl_urls.json
    ├── crawl_urls.csv
    ├── ...
```
