"""
Script de prueba para los módulos XSS y SQLi.
ADVERTENCIA: Solo usar en aplicaciones propias o con permiso explícito.
"""

from modules.xss import XSSModule
from modules.sqli import SQLiModule
from datetime import datetime

def test_xss_module():
    """Prueba el módulo XSS."""
    print("=" * 80)
    print("TEST: Módulo XSS")
    print("=" * 80)
    
    # Sitios de prueba (SOLO USAR EN ENTORNOS PROPIOS)
    # Estos son ejemplos - NO ESCANEAR SIN PERMISO
    test_targets = [
        "http://testphp.vulnweb.com/",  # Sitio de prueba público
    ]
    
    for target in test_targets:
        print(f"\n{'='*80}")
        print(f"Analizando: {target}")
        print(f"{'='*80}\n")
        
        config = {
            "target_url": target,
            "scan_timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "report_dir": f"reports/test_xss_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "timeout": 10,
            "max_xss_payloads": 5  # Limitar para prueba rápida
        }
        
        xss_module = XSSModule(config)
        xss_module.scan()
        
        findings = xss_module.get_results()
        
        print(f"\n📊 RESUMEN XSS:")
        print(f"   Total: {len(findings)}")
        
        by_severity = {}
        for finding in findings:
            severity = finding.get("severity", "unknown")
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        for severity in ["critical", "high", "medium", "low"]:
            count = by_severity.get(severity, 0)
            if count > 0:
                print(f"   {severity.upper()}: {count}")
        
        if findings:
            print(f"\n📝 HALLAZGOS DETALLADOS:")
            for i, finding in enumerate(findings, 1):
                print(f"\n   [{i}] {finding['title']}")
                print(f"       Severidad: {finding['severity'].upper()}")
                print(f"       Tipo: {finding['type']}")
                print(f"       URL: {finding['evidence'].get('url', 'N/A')}")
                if 'parameter' in finding['evidence']:
                    print(f"       Parámetro: {finding['evidence']['parameter']}")
        
        print(f"\n✅ Reporte exportado en: {config['report_dir']}/xss_findings.json")
        print("\n")

def test_sqli_module():
    """Prueba el módulo SQLi."""
    print("=" * 80)
    print("TEST: Módulo SQLi")
    print("=" * 80)
    
    test_targets = [
        "http://testphp.vulnweb.com/",  # Sitio de prueba público
    ]
    
    for target in test_targets:
        print(f"\n{'='*80}")
        print(f"Analizando: {target}")
        print(f"{'='*80}\n")
        
        config = {
            "target_url": target,
            "scan_timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
            "report_dir": f"reports/test_sqli_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "timeout": 10,
            "max_sqli_payloads": 8,  # Limitar para prueba rápida
            "use_sqlmap": False  # Deshabilitado para prueba rápida
        }
        
        sqli_module = SQLiModule(config)
        sqli_module.scan()
        
        findings = sqli_module.get_results()
        
        print(f"\n📊 RESUMEN SQLi:")
        print(f"   Total: {len(findings)}")
        
        by_severity = {}
        for finding in findings:
            severity = finding.get("severity", "unknown")
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        for severity in ["critical", "high", "medium", "low"]:
            count = by_severity.get(severity, 0)
            if count > 0:
                print(f"   {severity.upper()}: {count}")
        
        if findings:
            print(f"\n📝 HALLAZGOS DETALLADOS:")
            for i, finding in enumerate(findings, 1):
                print(f"\n   [{i}] {finding['title']}")
                print(f"       Severidad: {finding['severity'].upper()}")
                print(f"       Tipo: {finding['type']}")
                print(f"       URL: {finding['evidence'].get('url', 'N/A')}")
                if 'parameter' in finding['evidence']:
                    print(f"       Parámetro: {finding['evidence']['parameter']}")
                if 'sql_error' in finding['evidence']:
                    print(f"       Error SQL: {finding['evidence']['sql_error'][:100]}...")
        
        print(f"\n✅ Reporte exportado en: {config['report_dir']}/sqli_findings.json")
        print("\n")

def main():
    print("\n" + "="*80)
    print("WEBSEC FRAMEWORK - TEST DE MÓDULOS XSS Y SQLi")
    print("="*80)
    print("\n⚠️  ADVERTENCIA:")
    print("   Solo usar en aplicaciones propias o con permiso explícito.")
    print("   El escaneo no autorizado es ilegal.")
    print("="*80 + "\n")
    
    # Prueba XSS
    test_xss_module()
    
    # Prueba SQLi
    test_sqli_module()
    
    print("\n" + "="*80)
    print("TESTS COMPLETADOS")
    print("="*80 + "\n")

if __name__ == "__main__":
    main()
