# Guía de Instalación de Herramientas - Windows

Esta guía te ayudará a instalar SQLMap, OWASP ZAP y Nuclei en Windows.

---

## 📋 Requisitos Previos

- Windows 10/11
- Python 3.8+ instalado
- Git instalado (opcional pero recomendado)
- Conexión a Internet

---

## 🔧 Opción 1: Instalación Rápida (Recomendada)

### Script Automático

Crea un archivo `install_tools.bat` en la raíz del proyecto:

```batch
@echo off
echo ========================================
echo Instalando herramientas de seguridad
echo ========================================
echo.

REM Crear directorios
if not exist "tools" mkdir tools
if not exist "tools\sqlmap" mkdir tools\sqlmap
if not exist "tools\zap" mkdir tools\zap
if not exist "tools\nuclei" mkdir tools\nuclei

echo [1/3] Instalando SQLMap...
cd tools\sqlmap
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git .
if errorlevel 1 (
    echo Error: No se pudo clonar SQLMap. Asegurate de tener Git instalado.
) else (
    echo SQLMap instalado correctamente
)
cd ..\..

echo.
echo [2/3] Descargando OWASP ZAP...
echo Por favor, descarga ZAP manualmente desde:
echo https://github.com/zaproxy/zaproxy/releases/latest
echo Busca el archivo: ZAP_X_XX_X_windows.exe
echo.
pause

echo.
echo [3/3] Descargando Nuclei...
echo Por favor, descarga Nuclei manualmente desde:
echo https://github.com/projectdiscovery/nuclei/releases/latest
echo Busca el archivo: nuclei_X.X.X_windows_amd64.zip
echo Extrae nuclei.exe en tools\nuclei\
echo.
pause

echo.
echo ========================================
echo Instalacion completada
echo ========================================
echo.
echo Verifica la instalacion ejecutando:
echo python tests/test_external_tools.py
echo.
pause
```

Ejecuta el script:
```cmd
install_tools.bat
```

---

## 🔧 Opción 2: Instalación Manual Paso a Paso

### 1. SQLMap

#### Método A: Con Git (Recomendado)

```cmd
# Crear directorio
mkdir tools\sqlmap
cd tools\sqlmap

# Clonar repositorio
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git .

# Volver a la raíz
cd ..\..

# Probar instalación
python tools\sqlmap\sqlmap.py --version
```

#### Método B: Descarga Manual

1. Ve a: https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip
2. Descarga el archivo ZIP
3. Extrae el contenido en `tools\sqlmap\`
4. Verifica que exista `tools\sqlmap\sqlmap.py`

**Prueba:**
```cmd
python tools\sqlmap\sqlmap.py --version
```

---

### 2. OWASP ZAP

#### Método A: Instalador Oficial (Recomendado)

1. Ve a: https://www.zaproxy.org/download/
2. Descarga: **ZAP Windows (64) Installer**
3. Ejecuta el instalador
4. Instala en la ubicación por defecto: `C:\Program Files\ZAP\`
5. Añade ZAP al PATH:
   - Abre "Variables de entorno"
   - Edita la variable `Path`
   - Añade: `C:\Program Files\ZAP\`

**Prueba:**
```cmd
zap.bat -version
```

#### Método B: Portable

1. Ve a: https://github.com/zaproxy/zaproxy/releases/latest
2. Descarga: `ZAP_X_XX_X_windows.exe` (instalador) o `ZAP_X_XX_X_Crossplatform.zip`
3. Si usas el ZIP:
   - Extrae en `tools\zap\`
   - Verifica que exista `tools\zap\zap.bat`

**Prueba:**
```cmd
tools\zap\zap.bat -version
```

#### Método C: Chocolatey

Si tienes Chocolatey instalado:
```cmd
choco install owasp-zap
```

---

### 3. Nuclei

#### Método A: Descarga Directa (Recomendado)

1. Ve a: https://github.com/projectdiscovery/nuclei/releases/latest
2. Descarga: `nuclei_X.X.X_windows_amd64.zip`
3. Extrae el archivo
4. Copia `nuclei.exe` a `tools\nuclei\nuclei.exe`

**Prueba:**
```cmd
tools\nuclei\nuclei.exe -version
```

#### Método B: Con Go

Si tienes Go instalado:
```cmd
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

El binario se instalará en `%USERPROFILE%\go\bin\nuclei.exe`

**Prueba:**
```cmd
nuclei -version
```

#### Método C: Añadir al PATH

Para usar `nuclei` desde cualquier lugar:
1. Copia `nuclei.exe` a `C:\Windows\System32\` (requiere permisos de admin)
   
   O mejor:
2. Añade `tools\nuclei\` al PATH:
   - Abre "Variables de entorno"
   - Edita la variable `Path`
   - Añade la ruta completa: `C:\ruta\a\tu\proyecto\tools\nuclei\`

---

## 📁 Estructura de Directorios Esperada

Después de la instalación, deberías tener:

```
websec-framework/
├── tools/
│   ├── sqlmap/
│   │   ├── sqlmap.py          ← Script principal
│   │   ├── lib/
│   │   └── ...
│   ├── zap/
│   │   ├── zap.bat            ← Script de inicio (si es portable)
│   │   └── ...
│   └── nuclei/
│       └── nuclei.exe         ← Binario
└── ...
```

---

## ✅ Verificación de Instalación

Ejecuta el script de prueba:

```cmd
python tests/test_external_tools.py
```

Deberías ver algo como:

```
[INFO] PRUEBA: SQLMap Runner
[INFO] ✓ SQLMap encontrado: C:\...\tools\sqlmap\sqlmap.py

[INFO] PRUEBA: ZAP Runner
[INFO] ✓ ZAP encontrado: C:\Program Files\ZAP\zap.bat

[INFO] PRUEBA: Nuclei Runner
[INFO] ✓ Nuclei encontrado: C:\...\tools\nuclei\nuclei.exe
```

---

## 🔍 Verificación Manual

### SQLMap
```cmd
python tools\sqlmap\sqlmap.py --version
```
Salida esperada: `sqlmap/1.x.x`

### ZAP
```cmd
# Si está en PATH:
zap.bat -version

# Si es portable:
tools\zap\zap.bat -version

# O desde instalación:
"C:\Program Files\ZAP\zap.bat" -version
```
Salida esperada: `OWASP ZAP 2.x.x`

### Nuclei
```cmd
# Si está en PATH:
nuclei -version

# Si está en tools:
tools\nuclei\nuclei.exe -version
```
Salida esperada: `Nuclei Engine Version: vX.X.X`

---

## 🎯 Configuración del Framework

Después de instalar, actualiza tu configuración en `config/target.yaml`:

```yaml
# SQLMap
sqlmap_path: "tools/sqlmap/sqlmap.py"  # O "sqlmap" si está en PATH
sqlmap_timeout: 300

# OWASP ZAP
zap_path: "C:/Program Files/ZAP/zap.bat"  # O "zap.bat" si está en PATH
zap_timeout: 600
zap_api_port: 8090

# Nuclei
nuclei_path: "tools/nuclei/nuclei.exe"  # O "nuclei" si está en PATH
nuclei_timeout: 120
```

---

## 🚀 Primer Uso

### Ejemplo con SQLMap

```cmd
python
```

```python
from core.external.sqlmap_runner import SqlmapRunner

config = {"sqlmap_path": "tools/sqlmap/sqlmap.py"}
runner = SqlmapRunner(config)

findings = runner.run(
    target="http://testphp.vulnweb.com/artists.php?artist=1",
    risk=1,
    level=1,
    timeout=60
)

print(f"Hallazgos: {len(findings)}")
```

### Ejemplo con ZAP

```python
from core.external.zap_runner import ZapRunner

config = {"zap_path": "C:/Program Files/ZAP/zap.bat"}
runner = ZapRunner(config)

findings = runner.run(
    target="http://testphp.vulnweb.com",
    scan_mode="quick",
    timeout=60
)

print(f"Hallazgos: {len(findings)}")
```

### Ejemplo con Nuclei

```python
from core.external.nuclei_runner import NucleiRunner

config = {"nuclei_path": "tools/nuclei/nuclei.exe"}
runner = NucleiRunner(config)

findings = runner.run(
    target="http://testphp.vulnweb.com",
    severity=["high", "critical"],
    timeout=60
)

print(f"Hallazgos: {len(findings)}")
```

---

## 🐛 Troubleshooting

### Error: "python no se reconoce como comando"

**Solución:** Añade Python al PATH
1. Busca donde está instalado Python: `C:\Python3X\`
2. Añade al PATH: `C:\Python3X\` y `C:\Python3X\Scripts\`

### Error: "git no se reconoce como comando"

**Solución:** Instala Git desde https://git-scm.com/download/win

### Error: "No se puede ejecutar sqlmap.py"

**Solución:** Usa Python explícitamente:
```cmd
python tools\sqlmap\sqlmap.py --version
```

### Error: "Java no está instalado" (ZAP)

**Solución:** ZAP requiere Java 11+
1. Descarga Java desde: https://adoptium.net/
2. Instala Java
3. Reinicia el sistema

### Error: "nuclei.exe no es reconocido"

**Solución:** Usa la ruta completa:
```cmd
tools\nuclei\nuclei.exe -version
```

O añade al PATH como se explicó arriba.

### Error: "Access Denied" al copiar a System32

**Solución:** Ejecuta CMD como Administrador:
1. Busca "cmd" en el menú inicio
2. Click derecho → "Ejecutar como administrador"
3. Ejecuta el comando de copia

---

## 📦 Instalación con Dependencias Python

Si necesitas instalar dependencias adicionales:

```cmd
# Crear entorno virtual (recomendado)
python -m venv .venv

# Activar entorno virtual
.venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

---

## 🔄 Actualización de Herramientas

### SQLMap
```cmd
cd tools\sqlmap
git pull
cd ..\..
```

### ZAP
Descarga la nueva versión desde https://www.zaproxy.org/download/

### Nuclei
```cmd
# Si usaste Go:
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Si descargaste el binario:
# Descarga la nueva versión y reemplaza nuclei.exe
```

### Actualizar Templates de Nuclei
```cmd
tools\nuclei\nuclei.exe -update-templates
```

---

## 💡 Tips Adicionales

1. **Usa rutas absolutas** en la configuración para evitar problemas
2. **Ejecuta como Administrador** si tienes problemas de permisos
3. **Añade excepciones al antivirus** para las herramientas de seguridad
4. **Usa PowerShell** en lugar de CMD para mejor compatibilidad
5. **Verifica el PATH** con: `echo %PATH%`

---

## 📚 Recursos Adicionales

- **SQLMap Wiki**: https://github.com/sqlmapproject/sqlmap/wiki
- **ZAP Getting Started**: https://www.zaproxy.org/getting-started/
- **Nuclei Documentation**: https://nuclei.projectdiscovery.io/
- **Documentación del Framework**: `docs/EXTERNAL_INTEGRATIONS.md`

---

## ✅ Checklist de Instalación

- [ ] Python 3.8+ instalado y en PATH
- [ ] Git instalado (opcional)
- [ ] SQLMap descargado en `tools/sqlmap/`
- [ ] ZAP instalado (en Program Files o tools/zap/)
- [ ] Nuclei descargado en `tools/nuclei/`
- [ ] Java 11+ instalado (para ZAP)
- [ ] Verificación exitosa con `tests/test_external_tools.py`
- [ ] Configuración actualizada en `config/target.yaml`

---

**¿Necesitas ayuda?** Consulta la documentación completa en `docs/EXTERNAL_INTEGRATIONS.md`

**Desarrollado con ❤️ para la comunidad de seguridad web**
