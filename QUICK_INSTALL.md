# 🚀 Instalación Rápida - 5 Minutos

## ✨ Instalación Completamente Automática (Recomendado)

### Opción 1: Script Python (Multiplataforma)

```bash
python install_tools.py
```

Este script:
- ✅ Descarga e instala SQLMap automáticamente
- ✅ Descarga e instala ZAP en modo portable (sin instalador)
- ✅ Descarga e instala Nuclei automáticamente
- ✅ Verifica que todo funcione correctamente
- ✅ No requiere intervención manual

**Ventajas:**
- Completamente automático
- Funciona en Windows, Linux y macOS
- No requiere instaladores manuales
- ZAP en modo portable (no necesita permisos de admin)

### Opción 2: Script Batch (Solo Windows)

```cmd
install_tools.bat
```

---

## 📦 ¿Qué se Instala?

### 1️⃣ SQLMap
- **Ubicación:** `tools/sqlmap/`
- **Método:** Clonado desde GitHub o descarga ZIP
- **Tamaño:** ~10 MB

### 2️⃣ OWASP ZAP (Portable)
- **Ubicación:** `tools/zap/`
- **Método:** Descarga automática de versión Crossplatform
- **Tamaño:** ~200 MB
- **Requisito:** Java 11+ (se verifica automáticamente)

### 3️⃣ Nuclei
- **Ubicación:** `tools/nuclei/`
- **Método:** Descarga automática del binario
- **Tamaño:** ~20 MB
- **Incluye:** Templates actualizados automáticamente

---

## ⚡ Instalación Manual Rápida (Alternativa)

Si prefieres instalar manualmente:

### 1️⃣ SQLMap (2 minutos)

**Con Git:**
```cmd
mkdir tools\sqlmap
cd tools\sqlmap
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git .
cd ..\..
```

**Sin Git:**
1. Descarga: https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip
2. Extrae en `tools\sqlmap\`

**Verifica:**
```cmd
python tools\sqlmap\sqlmap.py --version
```

---

### 2️⃣ OWASP ZAP (1 minuto)

**Descarga manual:**
1. Descarga: https://www.zaproxy.org/download/
2. Ejecuta el instalador
3. Instala en `C:\Program Files\ZAP\`

**Requisito:** Java 11+ desde https://adoptium.net/

**Verifica:**
```cmd
"C:\Program Files\ZAP\zap.bat" -version
```

**Nota:** El script automático instala ZAP en modo portable sin necesidad de instalador.

---

### 3️⃣ Nuclei (1 minuto)

**Descarga directa:**
1. Ve a: https://github.com/projectdiscovery/nuclei/releases/latest
2. Descarga: `nuclei_X.X.X_windows_amd64.zip`
3. Extrae `nuclei.exe` en `tools\nuclei\`

**Verifica:**
```cmd
tools\nuclei\nuclei.exe -version
```

**Actualiza templates:**
```cmd
tools\nuclei\nuclei.exe -update-templates
```

---

## ✅ Verificación Final

```cmd
python tests/test_external_tools.py
```

Deberías ver:
```
[INFO] ✓ SQLMap encontrado
[INFO] ✓ ZAP encontrado
[INFO] ✓ Nuclei encontrado
```

---

## 🎯 Primer Uso

```python
from core.external.sqlmap_runner import SqlmapRunner
from core.external.zap_runner import ZapRunner
from core.external.nuclei_runner import NucleiRunner

# Configuración (rutas automáticas después de install_tools.py)
config = {
    "sqlmap_path": "tools/sqlmap/sqlmap.py",
    "zap_path": "tools/zap/zap.bat",  # o "tools/zap/zap.sh" en Linux/Mac
    "nuclei_path": "tools/nuclei/nuclei.exe"  # o "tools/nuclei/nuclei" en Linux/Mac
}

# Usar las herramientas
sqlmap = SqlmapRunner(config)
zap = ZapRunner(config)
nuclei = NucleiRunner(config)
```

---

## 🐛 Problemas Comunes

### "Git no reconocido"
→ No es necesario con `install_tools.py` (descarga ZIP automáticamente)

### "Python no reconocido"
→ Añade Python al PATH o usa la ruta completa: `C:\Python3X\python.exe install_tools.py`

### "Java no instalado" (para ZAP)
→ Instala Java 11+: https://adoptium.net/
→ ZAP se instala de todas formas, pero necesitarás Java para ejecutarlo

### "Error al descargar"
→ Verifica tu conexión a Internet
→ Intenta de nuevo (el script es idempotente)
→ Usa instalación manual como alternativa

---

## 💡 Ventajas de la Instalación Automática

✅ **Sin instaladores manuales**: Todo se descarga automáticamente
✅ **Modo portable**: ZAP no requiere permisos de administrador
✅ **Idempotente**: Puedes ejecutar el script múltiples veces sin problemas
✅ **Multiplataforma**: Funciona en Windows, Linux y macOS
✅ **Verificación automática**: Comprueba que todo funcione correctamente

---

## 📚 Documentación Completa

- **Guía detallada:** `docs/INSTALL_TOOLS_WINDOWS.md`
- **Documentación técnica:** `docs/EXTERNAL_INTEGRATIONS.md`
- **Ejemplos de uso:** `tests/example_usage.py`

---

**¿Listo?** Ejecuta `python install_tools.py` y comienza en 5 minutos! 🚀
