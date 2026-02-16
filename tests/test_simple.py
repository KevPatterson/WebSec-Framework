"""
Script de prueba simple para verificar que los módulos funcionan correctamente.
"""

from core.scanner import Scanner
from modules.headers import HeadersModule
from modules.xss import XSSModule
from modules.sqli import SQLiModule
from datetime import datetime
import os

def test_simple():
    """Prueba simple de los módulos."""
    
    # URL de prueba (sitio público de pruebas)
    target = "http://testphp.vulnweb.com/"
    
    print("=" * 80)
    print("TEST SIMPLE - WebSec Framework")
    print("=" * 80)
    print(f"\nObjetivo: {target}")
    print("Módulos: Headers, XSS, SQLi\n")
    
    # Configuración
    config = {
        "scan_timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
        "report_dir": f"reports/test_simple_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "timeout": 10,
        "max_xss_payloads": 5,
        "max_sqli_payloads": 5
    }
    
    # Crear scanner
    scanner = Scanner(target, config)
    
    # Registrar módulos
    print("Registrando módulos...")
    scanner.register_module(HeadersModule(scanner.config))
    scanner.register_module(XSSModule(scanner.config))
    scanner.register_module(SQLiModule(scanner.config))
    
    # Ejecutar escaneo
    print("\nIniciando escaneo...\n")
    scanner.run()
    
    # Mostrar resultados
    print("\n" + "=" * 80)
    print("RESULTADOS")
    print("=" * 80)
    
    findings = scanner.all_findings
    print(f"\nTotal de hallazgos: {len(findings)}")
    
    # Agrupar por severidad
    by_severity = {}
    for finding in findings:
        severity = finding.get("severity", "unknown")
        by_severity[severity] = by_severity.get(severity, 0) + 1
    
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = by_severity.get(severity, 0)
        if count > 0:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
            print(f"{emoji.get(severity, '⚪')} {severity.upper()}: {count}")
    
    # Agrupar por módulo
    print("\nPor módulo:")
    by_module = {}
    for finding in findings:
        ftype = finding.get("type", "unknown")
        module = ftype.split("_")[0] if "_" in ftype else ftype
        by_module[module] = by_module.get(module, 0) + 1
    
    for module, count in by_module.items():
        print(f"  - {module}: {count} hallazgos")
    
    # Mostrar algunos hallazgos
    if findings:
        print(f"\n📝 Primeros 3 hallazgos:")
        for i, finding in enumerate(findings[:3], 1):
            print(f"\n   [{i}] {finding['title']}")
            print(f"       Severidad: {finding['severity'].upper()}")
            print(f"       Tipo: {finding['type']}")
    
    # Verificar archivos generados
    print(f"\n📁 Archivos generados en: {config['report_dir']}/")
    if os.path.exists(config['report_dir']):
        files = os.listdir(config['report_dir'])
        for f in files:
            size = os.path.getsize(os.path.join(config['report_dir'], f))
            print(f"   - {f} ({size} bytes)")
    
    print("\n" + "=" * 80)
    print("TEST COMPLETADO")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    test_simple()
