"""
Script de prueba para verificar la exportación PDF.
"""

from core.pdf_exporter import PDFExporter
import os

def test_pdf_availability():
    """Verifica si wkhtmltopdf está disponible."""
    print("=" * 80)
    print("TEST: Verificación de wkhtmltopdf")
    print("=" * 80)
    
    exporter = PDFExporter()
    
    if exporter.is_available():
        print("✓ wkhtmltopdf está disponible")
        print(f"  Ruta: {exporter.wkhtmltopdf_path}")
        return True
    else:
        print("✗ wkhtmltopdf NO está disponible")
        print("\nInstrucciones de instalación:")
        print(exporter.get_installation_instructions())
        return False

def test_pdf_export():
    """Prueba la exportación de un reporte HTML existente a PDF."""
    print("\n" + "=" * 80)
    print("TEST: Exportación HTML a PDF")
    print("=" * 80)
    
    # Buscar un reporte HTML existente
    reports_dir = "reports"
    html_file = None
    
    for root, dirs, files in os.walk(reports_dir):
        for file in files:
            if file == "vulnerability_report.html":
                html_file = os.path.join(root, file)
                break
        if html_file:
            break
    
    if not html_file:
        print("✗ No se encontró ningún reporte HTML para probar")
        print("  Ejecuta primero: python test_simple.py")
        return False
    
    print(f"✓ Reporte HTML encontrado: {html_file}")
    
    # Exportar a PDF
    pdf_file = html_file.replace('.html', '_test.pdf')
    
    exporter = PDFExporter()
    
    print(f"  Exportando a: {pdf_file}")
    
    if exporter.export(html_file, pdf_file):
        print(f"✓ PDF generado exitosamente")
        
        # Verificar tamaño
        if os.path.exists(pdf_file):
            size = os.path.getsize(pdf_file)
            print(f"  Tamaño: {size:,} bytes ({size/1024:.1f} KB)")
            
            # Abrir el PDF
            print(f"\n  Abriendo PDF en el navegador...")
            os.system(f'start {pdf_file}')
            
            return True
        else:
            print("✗ El archivo PDF no se creó")
            return False
    else:
        print("✗ Error al generar PDF")
        return False

if __name__ == "__main__":
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "TEST DE EXPORTACIÓN PDF" + " " * 35 + "║")
    print("╚" + "=" * 78 + "╝")
    print()
    
    # Test 1: Verificar disponibilidad
    available = test_pdf_availability()
    
    if available:
        # Test 2: Exportar a PDF
        test_pdf_export()
    
    print("\n" + "=" * 80)
    print("Tests completados")
    print("=" * 80)
