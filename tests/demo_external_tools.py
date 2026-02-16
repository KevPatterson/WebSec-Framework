"""
Demostración de uso de SQLMap y ZAP
Ejecuta escaneos reales contra un target de prueba
"""
from core.external.sqlmap_runner import SqlmapRunner
from core.external.zap_runner import ZapRunner
from core.logger import get_logger
import json
from datetime import datetime

logger = get_logger("demo")

def demo_sqlmap():
    """Demostración de SQLMap"""
    print("\n" + "="*80)
    print("DEMO: SQLMap - SQL Injection Scanner")
    print("="*80)
    print()
    
    config = {
        "sqlmap_path": "tools/sqlmap/sqlmapproject-sqlmap-5a097c7/sqlmap.py",
        "sqlmap_timeout": 120
    }
    
    runner = SqlmapRunner(config)
    
    # Target vulnerable de prueba
    target = "http://testphp.vulnweb.com/artists.php?artist=1"
    
    print(f"Target: {target}")
    print("Configuración:")
    print("  - Risk: 1 (bajo)")
    print("  - Level: 1 (básico)")
    print("  - Threads: 1")
    print("  - Timeout: 60 segundos")
    print()
    print("Iniciando escaneo...")
    print("-" * 80)
    
    try:
        findings = runner.run(
            target=target,
            risk=1,
            level=1,
            threads=1,
            timeout=60
        )
        
        print()
        print(f"✓ Escaneo completado")
        print(f"  Hallazgos encontrados: {len(findings)}")
        
        if findings:
            print()
            print("Detalles de hallazgos:")
            print("-" * 80)
            for i, finding in enumerate(findings, 1):
                print(f"\n[{i}] {finding.get('type', 'Unknown')}")
                print(f"    Severidad: {finding.get('severity', 'N/A')}")
                if 'description' in finding:
                    desc = finding['description'][:100]
                    print(f"    Descripción: {desc}...")
                if 'payload' in finding:
                    print(f"    Payload: {finding['payload']}")
            
            # Guardar resultados
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"demo_sqlmap_{timestamp}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=2, ensure_ascii=False)
            print()
            print(f"✓ Resultados guardados en: {output_file}")
        else:
            print()
            print("ℹ No se encontraron vulnerabilidades SQL Injection")
            print("  (Esto puede ser normal si el target no es vulnerable)")
        
        return findings
        
    except Exception as e:
        print()
        print(f"✗ Error durante el escaneo: {e}")
        return []

def demo_zap():
    """Demostración de ZAP"""
    print("\n" + "="*80)
    print("DEMO: OWASP ZAP - Web Application Scanner")
    print("="*80)
    print()
    
    config = {
        "zap_path": "tools/zap/zap.bat",
        "zap_timeout": 120
    }
    
    runner = ZapRunner(config)
    
    # Verificar Java
    print("Verificando requisitos...")
    try:
        import subprocess
        result = subprocess.run(["java", "-version"], capture_output=True, timeout=5)
        if result.returncode == 0:
            print("✓ Java encontrado")
        else:
            print("✗ Java no encontrado")
            print("  ZAP requiere Java 11+")
            print("  Descarga desde: https://adoptium.net/")
            return []
    except:
        print("✗ Java no encontrado")
        print("  ZAP requiere Java 11+ para funcionar")
        print("  Descarga desde: https://adoptium.net/")
        print()
        print("ℹ Saltando demo de ZAP (requiere Java)")
        return []
    
    # Target de prueba
    target = "http://testphp.vulnweb.com/"
    
    print()
    print(f"Target: {target}")
    print("Configuración:")
    print("  - Modo: Quick Scan (rápido)")
    print("  - Formato: JSON")
    print("  - Timeout: 60 segundos")
    print()
    print("Iniciando escaneo...")
    print("-" * 80)
    print()
    print("NOTA: ZAP puede tardar varios minutos en iniciar la primera vez")
    print("      y puede mostrar ventanas emergentes.")
    print()
    
    try:
        findings = runner.run(
            target=target,
            scan_mode="quick",
            output_format="json",
            timeout=60
        )
        
        print()
        print(f"✓ Escaneo completado")
        print(f"  Hallazgos encontrados: {len(findings)}")
        
        if findings:
            print()
            print("Detalles de hallazgos:")
            print("-" * 80)
            
            # Agrupar por severidad
            by_severity = {}
            for finding in findings:
                sev = finding.get('severity', 'unknown')
                by_severity[sev] = by_severity.get(sev, 0) + 1
            
            print("\nPor severidad:")
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                if sev in by_severity:
                    print(f"  {sev.upper()}: {by_severity[sev]}")
            
            print("\nPrimeros 5 hallazgos:")
            for i, finding in enumerate(findings[:5], 1):
                print(f"\n[{i}] {finding.get('type', 'Unknown')}")
                print(f"    Severidad: {finding.get('severity', 'N/A')}")
                print(f"    Confianza: {finding.get('confidence', 'N/A')}")
                if 'url' in finding:
                    url = finding['url'][:60]
                    print(f"    URL: {url}...")
            
            # Guardar resultados
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"demo_zap_{timestamp}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(findings, f, indent=2, ensure_ascii=False)
            print()
            print(f"✓ Resultados guardados en: {output_file}")
        else:
            print()
            print("ℹ No se encontraron vulnerabilidades")
        
        return findings
        
    except Exception as e:
        print()
        print(f"✗ Error durante el escaneo: {e}")
        return []

def main():
    print("="*80)
    print("DEMOSTRACIÓN DE HERRAMIENTAS EXTERNAS")
    print("="*80)
    print()
    print("Este script ejecuta escaneos reales contra targets de prueba:")
    print("  - SQLMap: http://testphp.vulnweb.com/artists.php?artist=1")
    print("  - ZAP: http://testphp.vulnweb.com/")
    print()
    print("ADVERTENCIA: Los escaneos pueden tardar varios minutos")
    print()
    
    input("Presiona Enter para continuar...")
    
    # Ejecutar demos
    sqlmap_findings = demo_sqlmap()
    zap_findings = demo_zap()
    
    # Resumen final
    print("\n" + "="*80)
    print("RESUMEN FINAL")
    print("="*80)
    print()
    print(f"SQLMap: {len(sqlmap_findings)} hallazgos")
    print(f"ZAP: {len(zap_findings)} hallazgos")
    print(f"Total: {len(sqlmap_findings) + len(zap_findings)} hallazgos")
    print()
    
    if sqlmap_findings or zap_findings:
        print("✓ Las herramientas están funcionando correctamente")
        print()
        print("Puedes usar estas configuraciones en tu código:")
        print()
        print("config = {")
        print('    "sqlmap_path": "tools/sqlmap/sqlmapproject-sqlmap-5a097c7/sqlmap.py",')
        print('    "zap_path": "tools/zap/zap.bat",')
        print("}")
    else:
        print("ℹ No se encontraron vulnerabilidades o hubo errores")
        print("  Esto puede ser normal dependiendo del target y la configuración")
    
    print()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nDemo cancelada por el usuario")
    except Exception as e:
        print(f"\n\nError inesperado: {e}")
