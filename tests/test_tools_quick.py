"""
Prueba rápida de SQLMap y ZAP
"""
from core.external.sqlmap_runner import SqlmapRunner
from core.external.zap_runner import ZapRunner
from core.logger import get_logger

logger = get_logger("test")

print("="*80)
print("PRUEBA RÁPIDA DE HERRAMIENTAS EXTERNAS")
print("="*80)
print()

# Configuración
config = {
    "sqlmap_path": "tools/sqlmap/sqlmapproject-sqlmap-5a097c7/sqlmap.py",
    "sqlmap_timeout": 60,
    "zap_path": "tools/zap/zap.bat",
    "zap_timeout": 60
}

# Test SQLMap
print("[1/2] Probando SQLMap...")
print("-" * 80)
sqlmap = SqlmapRunner(config)
sqlmap_exec, bin_name, is_python = sqlmap._find_sqlmap_exec()

if sqlmap_exec:
    print(f"✓ SQLMap encontrado: {sqlmap_exec}")
    print(f"  Tipo: {'Python script' if is_python else 'Binario'}")
    print()
    
    # Verificar que funciona
    print("  Verificando que SQLMap funciona...")
    try:
        import subprocess
        result = subprocess.run(
            ["python", sqlmap_exec, "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"  ✓ SQLMap funcional: {version}")
        else:
            print(f"  ✗ Error al ejecutar SQLMap")
    except Exception as e:
        print(f"  ✗ Error: {e}")
else:
    print(f"✗ SQLMap no encontrado")
    print(f"  Buscando: {bin_name}")

print()

# Test ZAP
print("[2/2] Probando ZAP...")
print("-" * 80)
zap = ZapRunner(config)
zap_exec, bin_name = zap._find_zap_exec()

if zap_exec:
    print(f"✓ ZAP encontrado: {zap_exec}")
    print()
    
    # Verificar Java
    print("  Verificando Java (requerido por ZAP)...")
    try:
        import subprocess
        result = subprocess.run(
            ["java", "-version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            java_version = result.stderr.split('\n')[0] if result.stderr else "Instalado"
            print(f"  ✓ Java encontrado: {java_version}")
        else:
            print(f"  ✗ Java no encontrado")
    except Exception as e:
        print(f"  ✗ Java no encontrado: {e}")
        print(f"  Descarga Java desde: https://adoptium.net/")
else:
    print(f"✗ ZAP no encontrado")
    print(f"  Buscando: {bin_name}")

print()
print("="*80)
print("RESUMEN")
print("="*80)

if sqlmap_exec and zap_exec:
    print("✓ Ambas herramientas están instaladas y listas para usar")
    print()
    print("Configuración recomendada:")
    print(f'  sqlmap_path: "{config["sqlmap_path"]}"')
    print(f'  zap_path: "{config["zap_path"]}"')
elif sqlmap_exec:
    print("✓ SQLMap instalado")
    print("✗ ZAP no instalado")
elif zap_exec:
    print("✗ SQLMap no instalado")
    print("✓ ZAP instalado")
else:
    print("✗ Ninguna herramienta instalada")

print()
