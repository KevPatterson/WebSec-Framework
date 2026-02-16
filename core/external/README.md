# Integraciones Externas

Este directorio contiene las integraciones con herramientas de seguridad externas.

## Herramientas Integradas

### 1. SQLMap Runner (`sqlmap_runner.py`)
Integración profesional con SQLMap para detección de SQL Injection.

**Características:**
- Detección automática de binario (Python script y compilado)
- Soporte multiplataforma (Windows/Linux/macOS)
- Configuración avanzada (risk, level, threads, technique)
- POST data, cookies, headers personalizados
- Tamper scripts para evasión de WAF
- Parsing robusto de resultados

**Uso básico:**
```python
from core.external.sqlmap_runner import SqlmapRunner

config = {"sqlmap_path": "sqlmap", "sqlmap_timeout": 300}
runner = SqlmapRunner(config)

findings = runner.run(
    target="http://example.com/page.php?id=1",
    risk=2,
    level=2,
    threads=2
)
```

### 2. OWASP ZAP Runner (`zap_runner.py`)
Integración profesional con OWASP ZAP para escaneo de vulnerabilidades web.

**Características:**
- Detección automática de binario multiplataforma
- 4 modos de escaneo: quick, baseline, full, api
- Spider tradicional y AJAX spider
- Múltiples formatos de salida (JSON, XML, HTML)
- Soporte para contextos y autenticación
- Mapeo de severidades estándar

**Uso básico:**
```python
from core.external.zap_runner import ZapRunner

config = {"zap_path": "zap.sh", "zap_timeout": 600}
runner = ZapRunner(config)

findings = runner.run(
    target="http://example.com",
    scan_mode="quick",
    output_format="json"
)
```

### 3. Nuclei Runner (`nuclei_runner.py`)
Integración profesional con Nuclei para escaneo basado en templates.

**Características:**
- Templates personalizables
- Filtrado por severidad, tags, CVEs
- Headers y cookies personalizados
- Rate limiting y proxy
- Actualización automática de templates

**Uso básico:**
```python
from core.external.nuclei_runner import NucleiRunner

config = {"nuclei_path": "nuclei", "nuclei_timeout": 120}
runner = NucleiRunner(config)

findings = runner.run(
    target="http://example.com",
    severity=["high", "critical"],
    tags=["xss", "sqli"]
)
```

## Instalación de Herramientas

### SQLMap
```bash
# Opción 1: Clonar repositorio
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git tools/sqlmap

# Opción 2: Instalar en sistema
sudo apt-get install sqlmap  # Debian/Ubuntu
brew install sqlmap          # macOS
```

### OWASP ZAP
```bash
# Linux
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_unix.sh
chmod +x ZAP_2_14_0_unix.sh
./ZAP_2_14_0_unix.sh

# macOS
brew install --cask owasp-zap

# Windows: Descargar desde https://www.zaproxy.org/download/
```

### Nuclei
```bash
# Go install
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# O descargar binario
wget https://github.com/projectdiscovery/nuclei/releases/download/v2.9.0/nuclei_2.9.0_linux_amd64.zip
unzip nuclei_2.9.0_linux_amd64.zip
mv nuclei tools/nuclei/
```

## Configuración

Añade las siguientes opciones a tu archivo de configuración:

```yaml
# config/target.yaml

# SQLMap
sqlmap_path: "sqlmap"
sqlmap_timeout: 300

# OWASP ZAP
zap_path: "zap.sh"
zap_timeout: 600
zap_api_port: 8090
zap_api_key: "your-api-key"

# Nuclei
nuclei_path: "nuclei"
nuclei_timeout: 120
nuclei_templates: "tools/nuclei-templates"
```

## Ubicaciones de Búsqueda

Los runners buscan los binarios en el siguiente orden:

1. **PATH del sistema** (comando global)
2. **Raíz del proyecto** (`./sqlmap.py`, `./zap.sh`, `./nuclei`)
3. **Directorio tools/** (`tools/sqlmap/`, `tools/zap/`, `tools/nuclei/`)
4. **Directorio específico de plataforma** (`windows/`, `linux/`)

## Formato de Resultados

Todos los runners retornan una lista de diccionarios con el siguiente formato estándar:

```python
[
    {
        "type": "SQL Injection",           # Tipo de vulnerabilidad
        "severity": "high",                # Severidad (critical/high/medium/low/info)
        "description": "...",              # Descripción detallada
        "url": "http://example.com/...",   # URL afectada (si aplica)
        "tool": "sqlmap"                   # Herramienta que lo detectó
        # ... campos adicionales específicos de cada herramienta
    }
]
```

## Testing

Ejecuta el script de prueba para verificar las integraciones:

```bash
python tests/test_external_tools.py
```

Este script:
- Verifica la detección de binarios
- Ejecuta escaneos de prueba
- Muestra un reporte consolidado
- Funciona incluso si las herramientas no están instaladas

## Documentación Completa

Para documentación detallada, ejemplos avanzados y troubleshooting, consulta:

📖 **[docs/EXTERNAL_INTEGRATIONS.md](../../docs/EXTERNAL_INTEGRATIONS.md)**

## Mejores Prácticas

1. **Usa timeouts apropiados**: Escaneos completos pueden tardar mucho
2. **Comienza con escaneos rápidos**: Usa configuraciones básicas para pruebas iniciales
3. **Valida targets**: Asegúrate de tener permiso para escanear
4. **Revisa logs**: Los runners generan logs detallados para debugging
5. **Combina herramientas**: Usa SQLMap para SQL injection y ZAP para otras vulnerabilidades

## Soporte

- SQLMap: https://github.com/sqlmapproject/sqlmap/wiki
- OWASP ZAP: https://www.zaproxy.org/docs/
- Nuclei: https://nuclei.projectdiscovery.io/

---

**Desarrollado con ❤️ para la comunidad de seguridad web**
