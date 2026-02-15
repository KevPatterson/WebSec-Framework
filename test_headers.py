"""
Script de prueba rápida para el módulo de Security Headers.
Prueba contra sitios públicos conocidos.
"""

from modules.headers import HeadersModule
from datetime import datetime

def test_headers_module():
    """Prueba el módulo de headers contra varios sitios."""
    
    # Sitios de prueba (públicos y conocidos)
    test_targets = [
        "https://example.com",
        "https://github.com",
        "https://google.com"
    ]
    
    print("=" * 80)
    print("TEST: Módulo de Security Headers")
    print("=" * 80)
    
    for target in test_targets:
        print(f"\n{'='*80}")
        print(f"Analizando: {target}")
        print(f"{'='*80}\n")
        
        # Configuración
        config = {
            "target_url": target,
            "scan_timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "report_dir": f"reports/test_headers_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        }
        
        # Crear y ejecutar módulo
        headers_module = HeadersModule(config)
        headers_module.scan()
        
        # Mostrar resultados
        findings = headers_module.get_results()
        
        print(f"\n📊 RESUMEN DE HALLAZGOS:")
        print(f"   Total: {len(findings)}")
        
        by_severity = {}
        for finding in findings:
            severity = finding.get("severity", "unknown")
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = by_severity.get(severity, 0)
            if count > 0:
                print(f"   {severity.upper()}: {count}")
        
        print(f"\n📝 HALLAZGOS DETALLADOS:")
        for i, finding in enumerate(findings, 1):
            print(f"\n   [{i}] {finding['title']}")
            print(f"       Severidad: {finding['severity'].upper()}")
            print(f"       Tipo: {finding['type']}")
            if finding.get('evidence', {}).get('current_value'):
                print(f"       Valor actual: {finding['evidence']['current_value']}")
        
        print(f"\n✅ Reporte exportado en: {config['report_dir']}/headers_findings.json")
        print("\n")

if __name__ == "__main__":
    test_headers_module()
