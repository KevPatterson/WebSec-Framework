# Integraciones Externas

Este documento describe las integraciones con herramientas externas de seguridad: SQLMap, OWASP ZAP y Nuclei.

## Tabla de Contenidos

- [SQLMap Runner](#sqlmap-runner)
- [OWASP ZAP Runner](#owasp-zap-runner)
- [Nuclei Runner](#nuclei-runner)
- [Instalación de Herramientas](#instalación-de-herramientas)
- [Configuración](#configuración)
- [Ejemplos de Uso](#ejemplos-de-uso)

---

## SQLMap Runner

### Descripción

SQLMap es una herramienta de código abierto para detectar y explotar vulnerabilidades de inyección SQL. Nuestra integración permite ejecutar escaneos automatizados y parsear los resultados.

### Características

- ✅ Detección automática del binario en múltiples ubicaciones
- ✅ Soporte para Python script y binarios compilados
- ✅ Configuración de riesgo y nivel de tests
- ✅ Soporte para POST data, cookies y headers personalizados
- ✅ Múltiples targets (lista de URLs)
- ✅ Tamper scripts
- ✅ Parsing robusto de resultados (logs, CSV, stdout)
- ✅ Timeout configurable
- ✅ Validación de permisos en Linux

### Parámetros Principales

```python
runner.run(
    target="http://example.com/page.php?id=1",  # URL objetivo
    data="username=admin&password=test",         # POST data (opcional)
    risk=2,                                      # Nivel de riesgo (1-3)
    level=1,                                     # Nivel de tests (1-5)
    threads=1,                                   # Número de threads
    technique="BEUSTQ",                          # Técnicas SQL
    dbms="MySQL",                                # DBMS específico
    cookie="session=abc123",                     # Cookies
    headers={"X-Custom": "value"},               # Headers personalizados
    tamper=["space2comment", "between"],         # Scripts de evasión
    timeout=300                                  # Timeout en segundos
)
```

### Ubicaciones de Búsqueda

El runner busca SQLMap en el siguiente orden:

1. PATH del sistema (`sqlmap` o `sqlmap.py`)
2. Raíz del proyecto (`sqlmap.py` o `sqlmap.exe`)
3. `tools/sqlmap/sqlmap.py`
4. `windows/sqlmap.exe` o `linux/sqlmap`

### Formato de Resultados

```python
[
    {
        "type": "SQL Injection",
        "severity": "high",
        "description": "Parameter: id (GET) is vulnerable",
        "injection_type": "boolean-based blind",
        "title": "AND boolean-based blind - WHERE or HAVING clause",
        "payload": "id=1 AND 1=1",
        "tool": "sqlmap"
    }
]
```

---

## OWASP ZAP Runner

### Descripción

OWASP ZAP (Zed Attack Proxy) es un escáner de seguridad web de código abierto. Nuestra integración soporta múltiples modos de escaneo y formatos de salida.

### Características

- ✅ Detección automática del binario multiplataforma
- ✅ Múltiples modos de escaneo (quick, baseline, full, api)
- ✅ Soporte para spider tradicional y AJAX spider
- ✅ Escaneo activo y pasivo
- ✅ Múltiples formatos de salida (JSON, XML, HTML, Markdown)
- ✅ Soporte para contextos y autenticación
- ✅ Parsing robusto de resultados
- ✅ Mapeo de severidades estándar
- ✅ Validación de permisos en Linux

### Modos de Escaneo

#### 1. Quick Scan (Rápido)
Escaneo básico y rápido para pruebas iniciales.

```python
runner.run(
    target="http://example.com",
    scan_mode="quick",
    output_format="json"
)
```

#### 2. Baseline Scan (Línea Base)
Escaneo pasivo sin ataques activos, ideal para CI/CD.

```python
runner.run(
    target="http://example.com",
    scan_mode="baseline",
    output_format="json"
)
```

#### 3. Full Scan (Completo)
Escaneo completo con spider y ataques activos.

```python
runner.run(
    target="http://example.com",
    scan_mode="full",
    spider=True,
    ajax_spider=True,
    active_scan=True,
    output_format="json"
)
```

#### 4. API Scan (APIs)
Escaneo especializado para APIs REST/OpenAPI.

```python
runner.run(
    target="http://api.example.com",
    scan_mode="api",
    output_format="json"
)
```

### Parámetros Principales

```python
runner.run(
    target="http://example.com",           # URL objetivo
    scan_mode="quick",                     # Modo de escaneo
    output_format="json",                  # Formato de salida
    spider=True,                           # Spider tradicional
    ajax_spider=False,                     # AJAX spider
    active_scan=True,                      # Escaneo activo
    context="/path/to/context.xml",        # Contexto ZAP
    user="testuser",                       # Usuario para auth
    timeout=600                            # Timeout en segundos
)
```

### Ubicaciones de Búsqueda

El runner busca ZAP en el siguiente orden:

1. PATH del sistema (`zap.sh`, `zap.bat`, `zap.exe`)
2. Raíz del proyecto
3. `tools/zap/`
4. `windows/` o `linux/`

### Formato de Resultados

```python
[
    {
        "type": "Cross Site Scripting (Reflected)",
        "severity": "high",
        "confidence": "Medium",
        "url": "http://example.com/search?q=test",
        "description": "Cross-site Scripting (XSS) is possible...",
        "solution": "Validate all input and encode output...",
        "reference": "https://owasp.org/www-community/attacks/xss/",
        "cwe_id": "79",
        "wasc_id": "8",
        "tool": "zap"
    }
]
```

### Mapeo de Severidades

ZAP usa códigos numéricos que se mapean a severidades estándar:

- `0` → `info`
- `1` → `low`
- `2` → `medium`
- `3` → `high`
- `4` → `critical`

---

## Nuclei Runner

### Descripción

Nuclei es un escáner de vulnerabilidades basado en plantillas. Ver documentación completa en el código fuente.

### Características Principales

- ✅ Plantillas personalizables
- ✅ Múltiples targets
- ✅ Filtrado por severidad, tags, CVEs
- ✅ Headers y cookies personalizados
- ✅ Rate limiting y proxy
- ✅ Actualización automática de templates

---

## Instalación de Herramientas

### SQLMap

#### Opción 1: Desde repositorio oficial
```bash
# Clonar repositorio
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git tools/sqlmap

# Ejecutar
python tools/sqlmap/sqlmap.py --version
```

#### Opción 2: Instalación en PATH
```bash
# Linux/Mac
sudo apt-get install sqlmap  # Debian/Ubuntu
brew install sqlmap          # macOS

# Windows
# Descargar desde https://github.com/sqlmapproject/sqlmap/releases
```

### OWASP ZAP

#### Opción 1: Instalación oficial
```bash
# Linux
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2_14_0_unix.sh
chmod +x ZAP_2_14_0_unix.sh
./ZAP_2_14_0_unix.sh

# Windows
# Descargar instalador desde https://www.zaproxy.org/download/

# macOS
brew install --cask owasp-zap
```

#### Opción 2: Docker
```bash
docker pull owasp/zap2docker-stable
docker run -t owasp/zap2docker-stable zap-baseline.py -t http://example.com
```

### Nuclei

```bash
# Linux/Mac
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# O descargar binario
wget https://github.com/projectdiscovery/nuclei/releases/download/v2.9.0/nuclei_2.9.0_linux_amd64.zip
unzip nuclei_2.9.0_linux_amd64.zip
mv nuclei tools/nuclei/

# Windows
# Descargar desde https://github.com/projectdiscovery/nuclei/releases
```

---

## Configuración

### Archivo de Configuración

Añade las siguientes opciones a tu archivo de configuración:

```yaml
# config/target.yaml

# SQLMap
sqlmap_path: "sqlmap"           # Ruta o nombre del binario
sqlmap_timeout: 300             # Timeout en segundos

# OWASP ZAP
zap_path: "zap.sh"              # Ruta o nombre del binario
zap_timeout: 600                # Timeout en segundos
zap_api_port: 8090              # Puerto para API REST
zap_api_key: "your-api-key"     # API key (opcional)

# Nuclei
nuclei_path: "nuclei"           # Ruta o nombre del binario
nuclei_timeout: 120             # Timeout en segundos
nuclei_templates: "tools/nuclei-templates"  # Ruta a templates
```

### Configuración Programática

```python
config = {
    "sqlmap_path": "sqlmap",
    "sqlmap_timeout": 300,
    "zap_path": "zap.sh",
    "zap_timeout": 600,
    "zap_api_port": 8090,
    "nuclei_path": "nuclei",
    "nuclei_timeout": 120
}
```

---

## Ejemplos de Uso

### Ejemplo 1: Escaneo SQLMap Básico

```python
from core.external.sqlmap_runner import SqlmapRunner

config = {"sqlmap_path": "sqlmap", "sqlmap_timeout": 300}
runner = SqlmapRunner(config)

findings = runner.run(
    target="http://testphp.vulnweb.com/artists.php?artist=1",
    risk=2,
    level=2,
    threads=2
)

for finding in findings:
    print(f"[{finding['severity']}] {finding['type']}: {finding['description']}")
```

### Ejemplo 2: Escaneo ZAP con Autenticación

```python
from core.external.zap_runner import ZapRunner

config = {"zap_path": "zap.sh", "zap_timeout": 600}
runner = ZapRunner(config)

findings = runner.run(
    target="http://example.com",
    scan_mode="full",
    spider=True,
    ajax_spider=True,
    active_scan=True,
    context="auth_context.xml",
    user="testuser"
)

for finding in findings:
    print(f"[{finding['severity']}] {finding['type']} at {finding['url']}")
```

### Ejemplo 3: Escaneo Combinado

```python
from core.external.sqlmap_runner import SqlmapRunner
from core.external.zap_runner import ZapRunner

config = {
    "sqlmap_path": "sqlmap",
    "sqlmap_timeout": 300,
    "zap_path": "zap.sh",
    "zap_timeout": 600
}

target = "http://example.com"

# SQLMap para inyecciones SQL
sqlmap = SqlmapRunner(config)
sql_findings = sqlmap.run(target=f"{target}/page.php?id=1", risk=2, level=2)

# ZAP para vulnerabilidades web generales
zap = ZapRunner(config)
zap_findings = zap.run(target=target, scan_mode="baseline")

# Combinar resultados
all_findings = sql_findings + zap_findings
print(f"Total de hallazgos: {len(all_findings)}")
```

### Ejemplo 4: Múltiples Targets

```python
# SQLMap con lista de URLs
targets = [
    "http://example.com/page1.php?id=1",
    "http://example.com/page2.php?user=admin",
    "http://example.com/page3.php?search=test"
]

findings = runner.run(url_list=targets, risk=1, level=1)
```

---

## Troubleshooting

### SQLMap no se encuentra

```
Error: sqlmap no está instalado o no se encuentra en el PATH
```

**Solución:**
1. Verifica que SQLMap esté instalado: `sqlmap --version`
2. Añade SQLMap al PATH o especifica la ruta completa en config
3. Coloca `sqlmap.py` en `tools/sqlmap/`

### ZAP no inicia

```
Error: ZAP no está instalado o no se encuentra en el PATH
```

**Solución:**
1. Verifica la instalación: `zap.sh -version` (Linux/Mac) o `zap.bat -version` (Windows)
2. Asegúrate de tener Java instalado (requerido por ZAP)
3. Especifica la ruta completa en config

### Timeout en escaneos

```
Error: Timeout: SQLMap no respondió en 300 segundos
```

**Solución:**
1. Aumenta el timeout en config: `sqlmap_timeout: 600`
2. Reduce el nivel de tests: `level=1` en lugar de `level=5`
3. Reduce el riesgo: `risk=1` en lugar de `risk=3`

### Permisos en Linux

```
Warning: El binario no es ejecutable
```

**Solución:**
```bash
chmod +x tools/sqlmap/sqlmap.py
chmod +x tools/zap/zap.sh
chmod +x tools/nuclei/nuclei
```

---

## Mejores Prácticas

1. **Usa timeouts apropiados**: Escaneos completos pueden tardar mucho tiempo
2. **Comienza con escaneos rápidos**: Usa `risk=1, level=1` para pruebas iniciales
3. **Valida targets**: Asegúrate de tener permiso para escanear los objetivos
4. **Revisa logs**: Los runners generan logs detallados para debugging
5. **Combina herramientas**: Usa SQLMap para SQL injection y ZAP para otras vulnerabilidades
6. **Actualiza regularmente**: Mantén las herramientas actualizadas para mejores resultados

---

## Referencias

- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [Nuclei Documentation](https://nuclei.projectdiscovery.io/)
