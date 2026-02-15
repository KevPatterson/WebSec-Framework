"""
Ejemplo de uso del framework WebSec con el módulo de Security Headers.
Demuestra cómo ejecutar un escaneo completo.
"""

from core.scanner import Scanner
from modules.headers import HeadersModule
from datetime import datetime

def main():
    """Ejecuta un escaneo de ejemplo."""
    
    # Configuración
    target_url = "https://github.com"
    
    print("=" * 80)
    print("WebSec Framework - Ejemplo de Escaneo de Security Headers")
    print("=" * 80)
    print(f"\nObjetivo: {target_url}\n")
    
    # Crear configuración compartida
    config = {
        "scan_timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
        "report_dir": f"reports/example_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    }
    
    # Crear scanner
    scanner = Scanner(target_url, config)
    
    # Registrar módulo de headers
    scanner.register_module(HeadersModule(config))
    
    # Ejecutar escaneo
    print("🔍 Iniciando escaneo...\n")
    scanner.run()
    
    # Mostrar resumen
    print("\n" + "=" * 80)
    print("📊 RESUMEN DEL ESCANEO")
    print("=" * 80)
    
    findings = scanner.all_findings
    print(f"\nTotal de hallazgos: {len(findings)}")
    
    by_severity = {}
    for finding in findings:
        severity = finding.get("severity", "unknown")
        by_severity[severity] = by_severity.get(severity, 0) + 1
    
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = by_severity.get(severity, 0)
        if count > 0:
            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
            print(f"{emoji.get(severity, '⚪')} {severity.upper()}: {count}")
    
    print(f"\n✅ Reportes generados en: {config['report_dir']}/")
    print(f"   - headers_findings.json")
    print(f"   - vulnerability_scan_consolidated.json")
    print("\n")

if __name__ == "__main__":
    main()
