"""
Test completo del framework con exportación PDF.
"""

from core.scanner import Scanner
from modules.headers import HeadersModule
from modules.xss import XSSModule
from modules.sqli import SQLiModule
from datetime import datetime
import os

def test_full_scan_with_pdf():
    """Test completo con exportación PDF."""
    
    print("\n" + "=" * 80)
    print("TEST COMPLETO - WebSec Framework con Exportación PDF")
    print("=" * 80)
    
    target = "http://testphp.vulnweb.com/"
    print(f"\nObjetivo: {target}")
    print("Módulos: Headers, XSS, SQLi")
    print("Exportación: HTML + PDF")
    
    # Configuración
    scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    config = {
        "target_url": target,
        "scan_timestamp": scan_timestamp,
        "report_dir": f"reports/test_full_pdf_{scan_timestamp}",
        "export_pdf": True  # ⭐ Habilitar exportación PDF
    }
    
    # Crear scanner
    scanner = Scanner(target, config)
    
    # Registrar módulos
    print("\nRegistrando módulos...")
    scanner.register_module(HeadersModule(scanner.config))
    scanner.register_module(XSSModule(scanner.config))
    scanner.register_module(SQLiModule(scanner.config))
    
    # Ejecutar escaneo
    print("\nIniciando escaneo con exportación PDF...\n")
    scanner.run()
    
    # Verificar archivos generados
    print("\n" + "=" * 80)
    print("VERIFICACIÓN DE ARCHIVOS GENERADOS")
    print("=" * 80)
    
    report_dir = config['report_dir']
    
    expected_files = [
        "headers_findings.json",
        "xss_findings.json",
        "sqli_findings.json",
        "vulnerability_scan_consolidated.json",
        "vulnerability_report.html",
        "vulnerability_report.pdf"  # ⭐ Verificar PDF
    ]
    
    all_files_exist = True
    
    for filename in expected_files:
        filepath = os.path.join(report_dir, filename)
        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            print(f"✓ {filename} ({size:,} bytes)")
        else:
            print(f"✗ {filename} - NO ENCONTRADO")
            all_files_exist = False
    
    # Resumen
    print("\n" + "=" * 80)
    print("RESUMEN")
    print("=" * 80)
    
    if all_files_exist:
        print("\n✅ TODOS LOS ARCHIVOS GENERADOS CORRECTAMENTE")
        print(f"   Incluyendo reporte PDF: {report_dir}/vulnerability_report.pdf")
        
        # Abrir PDF
        pdf_path = os.path.join(report_dir, "vulnerability_report.pdf")
        print(f"\n📄 Abriendo PDF...")
        os.system(f'start {pdf_path}')
    else:
        print("\n⚠ ALGUNOS ARCHIVOS NO SE GENERARON")
    
    print("\n" + "=" * 80)
    print("TEST COMPLETADO")
    print("=" * 80)

if __name__ == "__main__":
    test_full_scan_with_pdf()
