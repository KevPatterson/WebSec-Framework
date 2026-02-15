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


def example_csrf_cors_lfi():
    """Ejemplo de uso de los módulos CSRF, CORS y LFI/RFI."""
    from modules.csrf import CSRFModule
    from modules.cors import CORSModule
    from modules.lfi import LFIModule
    
    target_url = "http://testphp.vulnweb.com"
    
    print("\n" + "=" * 80)
    print("WebSec Framework - Ejemplo CSRF, CORS y LFI/RFI")
    print("=" * 80)
    print(f"\nObjetivo: {target_url}\n")
    
    # Configuración
    config = {
        "target_url": target_url,
        "scan_timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
        "report_dir": f"reports/example_csrf_cors_lfi_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    }
    
    # Crear scanner
    scanner = Scanner(target_url, config)
    
    # Registrar módulos de seguridad
    print("📦 Registrando módulos:")
    print("  - CSRF Detection (CVSS 8.8)")
    print("  - CORS Misconfiguration (CVSS 7.5-9.1)")
    print("  - LFI/RFI Detection (CVSS 7.5-9.1)")
    
    scanner.register_module(CSRFModule(config))
    scanner.register_module(CORSModule(config))
    scanner.register_module(LFIModule(config))
    
    # Ejecutar escaneo
    print("\n🔍 Iniciando escaneo de seguridad...\n")
    scanner.run()
    
    # Mostrar resumen
    print("\n" + "=" * 80)
    print("📊 RESUMEN DEL ESCANEO")
    print("=" * 80)
    
    findings = scanner.all_findings
    print(f"\nTotal de hallazgos: {len(findings)}")
    
    if findings:
        by_severity = {}
        by_module = {}
        
        for finding in findings:
            severity = finding.get("severity", "unknown")
            vuln = finding.get("vulnerability", "Unknown")
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_module[vuln] = by_module.get(vuln, 0) + 1
        
        print("\nPor severidad:")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = by_severity.get(severity, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(severity, "⚫")
                print(f"  {emoji} {severity.upper()}: {count}")
        
        print("\nPor tipo de vulnerabilidad:")
        for vuln, count in by_module.items():
            print(f"  • {vuln}: {count}")
    
    print(f"\n📁 Reportes generados en: {config['report_dir']}")
    print("=" * 80)

if __name__ == "__main__":
    # Ejecutar ejemplo de headers
    main()
    
    # Descomentar para ejecutar ejemplo de CSRF, CORS y LFI
    # example_csrf_cors_lfi()
