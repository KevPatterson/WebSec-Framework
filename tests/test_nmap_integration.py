"""
Script de prueba para la integración de Nmap.
Demuestra el uso del módulo de escaneo de puertos.
"""

import sys
import os

# Añadir el directorio raíz al path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.external.nmap_runner import NmapRunner
from modules.port_scan import PortScanModule
from core.logger import get_logger
from datetime import datetime


def test_nmap_availability():
    """Prueba si Nmap está disponible."""
    print("\n" + "="*60)
    print("TEST 1: Verificar disponibilidad de Nmap")
    print("="*60)
    
    config = {}
    nmap_runner = NmapRunner(config)
    
    if nmap_runner.is_available():
        print("✅ Nmap está disponible y funcional")
        return True
    else:
        print("❌ Nmap no está disponible")
        print("\nPara instalar:")
        print("  1. Instala Nmap en tu sistema: https://nmap.org/download.html")
        print("  2. Instala python-nmap: pip install python-nmap")
        return False


def test_quick_scan():
    """Prueba un escaneo rápido."""
    print("\n" + "="*60)
    print("TEST 2: Escaneo Rápido de Puertos Comunes")
    print("="*60)
    
    # Usar scanme.nmap.org (servidor de pruebas oficial de Nmap)
    target = "scanme.nmap.org"
    print(f"\nObjetivo: {target}")
    print("Nota: Este es un servidor de pruebas oficial de Nmap")
    
    config = {"nmap_timeout": 120}
    nmap_runner = NmapRunner(config)
    
    if not nmap_runner.is_available():
        print("❌ Nmap no disponible, saltando prueba")
        return
    
    print("\nEjecutando escaneo rápido...")
    results = nmap_runner.quick_scan(target)
    
    if results:
        print("✅ Escaneo completado")
        
        # Mostrar resumen
        summary = nmap_runner.get_open_ports_summary(results)
        print(f"\nPuertos abiertos encontrados: {len(summary)}")
        
        for port_info in summary:
            print(f"  - Puerto {port_info['port']}/{port_info['protocol']}: "
                  f"{port_info['service']} {port_info['product']} {port_info['version']}")
    else:
        print("❌ No se obtuvieron resultados")


def test_port_scan_module():
    """Prueba el módulo completo de escaneo de puertos."""
    print("\n" + "="*60)
    print("TEST 3: Módulo PortScanModule Completo")
    print("="*60)
    
    target = "http://scanme.nmap.org"
    print(f"\nObjetivo: {target}")
    
    config = {
        "target_url": target,
        "nmap_scan_type": "quick",
        "scan_timestamp": datetime.now().strftime("%Y%m%d_%H%M%S"),
        "report_dir": "reports/test_nmap"
    }
    
    module = PortScanModule(config)
    
    if not module.nmap_runner.is_available():
        print("❌ Nmap no disponible, saltando prueba")
        return
    
    print("\nEjecutando módulo de escaneo...")
    module.scan()
    
    findings = module.get_results()
    print(f"\n✅ Módulo ejecutado: {len(findings)} hallazgos")
    
    # Mostrar hallazgos por severidad
    by_severity = {}
    for finding in findings:
        severity = finding.get("severity", "unknown")
        by_severity[severity] = by_severity.get(severity, 0) + 1
    
    print("\nHallazgos por severidad:")
    for severity, count in sorted(by_severity.items()):
        print(f"  - {severity.upper()}: {count}")
    
    # Mostrar algunos hallazgos de ejemplo
    print("\nEjemplos de hallazgos:")
    for i, finding in enumerate(findings[:3], 1):
        print(f"\n  {i}. {finding['title']}")
        print(f"     Severidad: {finding['severity']}")
        print(f"     Puerto: {finding['evidence']['port']}/{finding['evidence']['protocol']}")
        print(f"     Servicio: {finding['evidence']['service']}")


def test_service_detection():
    """Prueba la detección de servicios."""
    print("\n" + "="*60)
    print("TEST 4: Detección de Servicios y Versiones")
    print("="*60)
    
    target = "scanme.nmap.org"
    print(f"\nObjetivo: {target}")
    
    config = {}
    nmap_runner = NmapRunner(config)
    
    if not nmap_runner.is_available():
        print("❌ Nmap no disponible, saltando prueba")
        return
    
    print("\nEjecutando escaneo de servicios en puertos comunes...")
    results = nmap_runner.service_scan(target, ports="22,80,443")
    
    if results:
        print("✅ Escaneo de servicios completado")
        
        summary = nmap_runner.get_open_ports_summary(results)
        print(f"\nServicios detectados: {len(summary)}")
        
        for port_info in summary:
            service_str = f"{port_info['service']}"
            if port_info['product']:
                service_str += f" - {port_info['product']}"
            if port_info['version']:
                service_str += f" {port_info['version']}"
            
            print(f"\n  Puerto {port_info['port']}/{port_info['protocol']}:")
            print(f"    Servicio: {service_str}")
    else:
        print("❌ No se obtuvieron resultados")


def main():
    """Ejecuta todas las pruebas."""
    logger = get_logger("test_nmap")
    
    print("\n" + "="*60)
    print("PRUEBAS DE INTEGRACIÓN DE NMAP")
    print("="*60)
    print("\nEstas pruebas utilizan scanme.nmap.org, un servidor")
    print("de pruebas oficial proporcionado por el proyecto Nmap.")
    print("="*60)
    
    # Test 1: Disponibilidad
    if not test_nmap_availability():
        print("\n⚠️  Nmap no está disponible. Instálalo para continuar.")
        return
    
    # Test 2: Escaneo rápido
    test_quick_scan()
    
    # Test 3: Módulo completo
    test_port_scan_module()
    
    # Test 4: Detección de servicios
    test_service_detection()
    
    print("\n" + "="*60)
    print("PRUEBAS COMPLETADAS")
    print("="*60)
    print("\nPara usar Nmap en tu proyecto:")
    print("  python run.py https://tu-objetivo.com --nmap")
    print("\nPara más información:")
    print("  Ver docs/NMAP_INTEGRATION.md")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
