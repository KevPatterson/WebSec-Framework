"""
Ejemplo de uso del PayloadManager centralizado.
Demuestra carga única, caching y payloads personalizados.
"""
from core.payload_manager import PayloadManager


def main():
    # Configuración
    config = {
        'payloads_dir': 'payloads'
    }
    
    # Crear gestor de payloads (Singleton)
    payload_mgr = PayloadManager(config)
    
    # Ejemplo 1: Obtener payloads XSS
    print("=== Ejemplo 1: Payloads XSS ===")
    xss_payloads = payload_mgr.get_payloads('xss', max_count=5)
    print(f"Payloads XSS cargados: {len(xss_payloads)}")
    for i, payload in enumerate(xss_payloads, 1):
        print(f"{i}. {payload[:50]}...")
    
    # Ejemplo 2: Obtener payloads SQLi
    print("\n=== Ejemplo 2: Payloads SQLi ===")
    sqli_payloads = payload_mgr.get_payloads('sqli', max_count=5)
    print(f"Payloads SQLi cargados: {len(sqli_payloads)}")
    for i, payload in enumerate(sqli_payloads, 1):
        print(f"{i}. {payload}")
    
    # Ejemplo 3: Obtener todos los payloads LFI
    print("\n=== Ejemplo 3: Todos los Payloads LFI ===")
    lfi_payloads = payload_mgr.get_payloads('lfi')
    print(f"Total payloads LFI: {len(lfi_payloads)}")
    
    # Ejemplo 4: Añadir payloads personalizados
    print("\n=== Ejemplo 4: Payloads Personalizados ===")
    custom_payloads = [
        "<img src=x onerror=alert(document.domain)>",
        "<svg/onload=alert(1)>",
        "javascript:alert(document.cookie)"
    ]
    
    payload_mgr.add_custom_payloads('xss', custom_payloads)
    print(f"Añadidos {len(custom_payloads)} payloads personalizados")
    
    # Verificar que se añadieron
    xss_all = payload_mgr.get_payloads('xss')
    print(f"Total payloads XSS ahora: {len(xss_all)}")
    
    # Ejemplo 5: Singleton pattern
    print("\n=== Ejemplo 5: Singleton Pattern ===")
    
    # Crear otra instancia
    payload_mgr2 = PayloadManager()
    
    # Verificar que es la misma instancia
    print(f"¿Misma instancia? {payload_mgr is payload_mgr2}")
    print(f"Payloads XSS en mgr2: {len(payload_mgr2.get_payloads('xss'))}")
    
    # Ejemplo 6: Recargar payloads
    print("\n=== Ejemplo 6: Recargar Payloads ===")
    print("Recargando payloads desde disco...")
    payload_mgr.reload_payloads()
    
    # Los payloads personalizados se pierden al recargar
    xss_reloaded = payload_mgr.get_payloads('xss')
    print(f"Payloads XSS después de recargar: {len(xss_reloaded)}")
    
    # Ejemplo 7: Payloads por defecto
    print("\n=== Ejemplo 7: Payloads por Defecto ===")
    
    # Tipo de vulnerabilidad sin archivo
    default_payloads = payload_mgr.get_payloads('nonexistent_type')
    print(f"Payloads por defecto para tipo inexistente: {len(default_payloads)}")


if __name__ == "__main__":
    main()
