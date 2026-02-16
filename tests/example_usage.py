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


def example_external_tools():
    """Ejemplo de uso de las integraciones externas (SQLMap y ZAP)."""
    from core.external.sqlmap_runner import SqlmapRunner
    from core.external.zap_runner import ZapRunner
    from core.external.nuclei_runner import NucleiRunner
    
    print("\n" + "=" * 80)
    print("WebSec Framework - Ejemplo de Integraciones Externas")
    print("=" * 80)
    
    # Configuración
    config = {
        "sqlmap_path": "sqlmap",
        "sqlmap_timeout": 120,
        "zap_path": "zap.sh",
        "zap_timeout": 120,
        "nuclei_path": "nuclei",
        "nuclei_timeout": 60
    }
    
    target = "http://testphp.vulnweb.com"
    
    print(f"\nObjetivo: {target}\n")
    
    all_findings = []
    
    # SQLMap - SQL Injection Detection
    print("=" * 80)
    print("🔍 SQLMap - Detección de SQL Injection")
    print("=" * 80)
    
    sqlmap = SqlmapRunner(config)
    sqlmap_exec, _, _ = sqlmap._find_sqlmap_exec()
    
    if sqlmap_exec:
        print(f"✓ SQLMap encontrado: {sqlmap_exec}")
        print(f"  Target: {target}/artists.php?artist=1")
        print("  Ejecutando escaneo (risk=1, level=1)...\n")
        
        try:
            sql_findings = sqlmap.run(
                target=f"{target}/artists.php?artist=1",
                risk=1,
                level=1,
                threads=1,
                timeout=60
            )
            
            print(f"✓ Escaneo completado: {len(sql_findings)} hallazgos")
            all_findings.extend(sql_findings)
            
            if sql_findings:
                print("\nPrimeros hallazgos:")
                for i, finding in enumerate(sql_findings[:3], 1):
                    print(f"  {i}. [{finding.get('severity', 'N/A')}] {finding.get('type', 'Unknown')}")
                    if 'description' in finding:
                        print(f"     {finding['description'][:80]}...")
        except Exception as e:
            print(f"✗ Error: {e}")
    else:
        print("✗ SQLMap no encontrado. Instálalo desde:")
        print("  https://github.com/sqlmapproject/sqlmap")
    
    # OWASP ZAP - Web Vulnerability Scanner
    print("\n" + "=" * 80)
    print("🔍 OWASP ZAP - Escaneo de Vulnerabilidades Web")
    print("=" * 80)
    
    zap = ZapRunner(config)
    zap_exec, _ = zap._find_zap_exec()
    
    if zap_exec:
        print(f"✓ ZAP encontrado: {zap_exec}")
        print(f"  Target: {target}")
        print("  Modo: Quick Scan")
        print("  Ejecutando escaneo...\n")
        
        try:
            zap_findings = zap.run(
                target=target,
                scan_mode="quick",
                output_format="json",
                timeout=60
            )
            
            print(f"✓ Escaneo completado: {len(zap_findings)} hallazgos")
            all_findings.extend(zap_findings)
            
            if zap_findings:
                print("\nPrimeros hallazgos:")
                for i, finding in enumerate(zap_findings[:3], 1):
                    print(f"  {i}. [{finding.get('severity', 'N/A')}] {finding.get('type', 'Unknown')}")
                    if 'url' in finding:
                        print(f"     URL: {finding['url'][:60]}...")
        except Exception as e:
            print(f"✗ Error: {e}")
    else:
        print("✗ ZAP no encontrado. Instálalo desde:")
        print("  https://www.zaproxy.org/download/")
    
    # Nuclei - Template-based Scanner
    print("\n" + "=" * 80)
    print("🔍 Nuclei - Escaneo Basado en Templates")
    print("=" * 80)
    
    nuclei = NucleiRunner(config)
    nuclei_exec, _ = nuclei._find_nuclei_exec()
    
    if nuclei_exec:
        print(f"✓ Nuclei encontrado: {nuclei_exec}")
        print(f"  Target: {target}")
        print("  Severidad: high,critical")
        print("  Ejecutando escaneo...\n")
        
        try:
            nuclei_findings = nuclei.run(
                target=target,
                severity=["high", "critical"],
                timeout=60
            )
            
            print(f"✓ Escaneo completado: {len(nuclei_findings)} hallazgos")
            all_findings.extend(nuclei_findings)
            
            if nuclei_findings:
                print("\nPrimeros hallazgos:")
                for i, finding in enumerate(nuclei_findings[:3], 1):
                    template = finding.get('template-id', 'Unknown')
                    severity = finding.get('info', {}).get('severity', 'N/A')
                    print(f"  {i}. [{severity}] {template}")
        except Exception as e:
            print(f"✗ Error: {e}")
    else:
        print("✗ Nuclei no encontrado. Instálalo desde:")
        print("  https://github.com/projectdiscovery/nuclei")
    
    # Resumen consolidado
    print("\n" + "=" * 80)
    print("📊 RESUMEN CONSOLIDADO")
    print("=" * 80)
    
    print(f"\nTotal de hallazgos: {len(all_findings)}")
    
    if all_findings:
        by_severity = {}
        by_tool = {}
        
        for finding in all_findings:
            severity = finding.get('severity', 'unknown')
            tool = finding.get('tool', 'unknown')
            
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_tool[tool] = by_tool.get(tool, 0) + 1
        
        print("\nPor severidad:")
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = by_severity.get(severity, 0)
            if count > 0:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}.get(severity, "⚫")
                print(f"  {emoji} {severity.upper()}: {count}")
        
        print("\nPor herramienta:")
        for tool, count in by_tool.items():
            print(f"  • {tool}: {count}")
    
    print("\n" + "=" * 80)
    print("💡 Tip: Para más opciones, consulta docs/EXTERNAL_INTEGRATIONS.md")
    print("=" * 80)


# Descomentar para ejecutar ejemplos específicos:
# if __name__ == "__main__":
#     example_external_tools()
