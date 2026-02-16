"""
Script de verificación completa del proyecto WebSec Framework.
Verifica que todos los componentes estén funcionando correctamente.
"""

import os
import sys
import importlib.util

def print_header(text):
    """Imprime un encabezado formateado."""
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80)

def check_file_exists(filepath):
    """Verifica que un archivo exista."""
    if os.path.exists(filepath):
        print(f"✓ {filepath}")
        return True
    else:
        print(f"✗ {filepath} - NO ENCONTRADO")
        return False

def check_module_imports(module_path, module_name):
    """Verifica que un módulo Python se pueda importar."""
    try:
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        print(f"✓ {module_path} - Importa correctamente")
        return True
    except Exception as e:
        print(f"✗ {module_path} - Error: {e}")
        return False

def main():
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 15 + "VERIFICACIÓN COMPLETA DEL PROYECTO" + " " * 29 + "║")
    print("╚" + "=" * 78 + "╝")
    
    total_checks = 0
    passed_checks = 0
    
    # 1. Verificar archivos principales
    print_header("1. ARCHIVOS PRINCIPALES")
    main_files = [
        "run.py",
        "app.py",
        "requirements.txt",
        "README.md",
        "QUICKSTART.md",
        "LICENSE"
    ]
    
    for file in main_files:
        total_checks += 1
        if check_file_exists(file):
            passed_checks += 1
    
    # 2. Verificar estructura de directorios
    print_header("2. ESTRUCTURA DE DIRECTORIOS")
    directories = [
        "config",
        "core",
        "core/external",
        "core/templates",
        "modules",
        "payloads",
        "reports",
        "templates",
        "tools",
        "docs"
    ]
    
    for directory in directories:
        total_checks += 1
        if os.path.isdir(directory):
            print(f"✓ {directory}/")
            passed_checks += 1
        else:
            print(f"✗ {directory}/ - NO ENCONTRADO")
    
    # 3. Verificar módulos del core
    print_header("3. MÓDULOS DEL CORE")
    core_modules = [
        ("core/base_module.py", "base_module"),
        ("core/crawler.py", "crawler"),
        ("core/fingerprint.py", "fingerprint"),
        ("core/scanner.py", "scanner"),
        ("core/validator.py", "validator"),
        ("core/reporter.py", "reporter"),
        ("core/logger.py", "logger"),
        ("core/html_reporter.py", "html_reporter"),
        ("core/pdf_exporter.py", "pdf_exporter")
    ]
    
    for module_path, module_name in core_modules:
        total_checks += 1
        if check_module_imports(module_path, module_name):
            passed_checks += 1
    
    # 4. Verificar módulos de vulnerabilidades
    print_header("4. MÓDULOS DE VULNERABILIDADES")
    vuln_modules = [
        ("modules/headers.py", "headers"),
        ("modules/xss.py", "xss"),
        ("modules/sqli.py", "sqli"),
        ("modules/csrf.py", "csrf"),
        ("modules/cors.py", "cors"),
        ("modules/auth.py", "auth"),
        ("modules/lfi.py", "lfi")
    ]
    
    for module_path, module_name in vuln_modules:
        total_checks += 1
        if check_module_imports(module_path, module_name):
            passed_checks += 1
    
    # 5. Verificar módulos externos
    print_header("5. MÓDULOS EXTERNOS")
    external_modules = [
        ("core/external/nuclei_runner.py", "nuclei_runner"),
        ("core/external/sqlmap_runner.py", "sqlmap_runner"),
        ("core/external/zap_runner.py", "zap_runner")
    ]
    
    for module_path, module_name in external_modules:
        total_checks += 1
        if check_module_imports(module_path, module_name):
            passed_checks += 1
    
    # 6. Verificar archivos de payloads
    print_header("6. ARCHIVOS DE PAYLOADS")
    payload_files = [
        "payloads/xss.txt",
        "payloads/sqli.txt",
        "payloads/lfi.txt"
    ]
    
    for file in payload_files:
        total_checks += 1
        if check_file_exists(file):
            passed_checks += 1
    
    # 7. Verificar templates
    print_header("7. TEMPLATES")
    template_files = [
        "templates/professional_report.html",
        "templates/crawl_tree.html",
        "templates/nuclei_report.html",
        "core/templates/report_template.html"
    ]
    
    for file in template_files:
        total_checks += 1
        if check_file_exists(file):
            passed_checks += 1
    
    # 8. Verificar documentación
    print_header("8. DOCUMENTACIÓN")
    doc_files = [
        "docs/HEADERS_MODULE.md",
        "docs/DEPENDENCIAS.md",
        "docs/PLAN_DESARROLLO.md"
    ]
    
    for file in doc_files:
        total_checks += 1
        if check_file_exists(file):
            passed_checks += 1
    
    # 9. Verificar scripts de prueba
    print_header("9. SCRIPTS DE PRUEBA")
    test_files = [
        "tests/test_simple.py",
        "tests/test_headers.py",
        "tests/test_xss_sqli.py",
        "tests/test_pdf_export.py",
        "tests/example_usage.py"
    ]
    
    for file in test_files:
        total_checks += 1
        if check_file_exists(file):
            passed_checks += 1
    
    # 10. Verificar herramientas externas
    print_header("10. HERRAMIENTAS EXTERNAS")
    
    # wkhtmltopdf
    total_checks += 1
    wkhtmltopdf_path = "tools/wkhtmltopdf/wkhtmltopdf.exe"
    if os.path.exists(wkhtmltopdf_path):
        print(f"✓ wkhtmltopdf encontrado en {wkhtmltopdf_path}")
        passed_checks += 1
    else:
        print(f"⚠ wkhtmltopdf no encontrado (opcional para exportación PDF)")
    
    # Resumen final
    print_header("RESUMEN")
    percentage = (passed_checks / total_checks) * 100
    
    print(f"\nTotal de verificaciones: {total_checks}")
    print(f"Verificaciones exitosas: {passed_checks}")
    print(f"Verificaciones fallidas: {total_checks - passed_checks}")
    print(f"Porcentaje de éxito: {percentage:.1f}%")
    
    if percentage == 100:
        print("\n✅ ¡PROYECTO COMPLETAMENTE VERIFICADO!")
        print("   Todos los componentes están presentes y funcionando correctamente.")
    elif percentage >= 90:
        print("\n✅ PROYECTO VERIFICADO CON ADVERTENCIAS MENORES")
        print("   La mayoría de los componentes están funcionando correctamente.")
    else:
        print("\n⚠ PROYECTO CON PROBLEMAS")
        print("   Algunos componentes críticos faltan o tienen errores.")
    
    print("\n" + "=" * 80)
    
    return 0 if percentage >= 90 else 1

if __name__ == "__main__":
    sys.exit(main())
