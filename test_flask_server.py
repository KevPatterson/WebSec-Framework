"""
Script de prueba para verificar que el servidor Flask funciona correctamente.
"""
import requests
import json
import os

def test_flask_server():
    base_url = "http://localhost:5000"
    
    print("="*60)
    print("PRUEBA DEL SERVIDOR FLASK")
    print("="*60)
    
    # 1. Verificar que el servidor esté corriendo
    print("\n1. Verificando que el servidor esté corriendo...")
    try:
        response = requests.get(base_url, timeout=5)
        if response.status_code == 200:
            print("   ✅ Servidor corriendo correctamente")
        else:
            print(f"   ❌ Servidor respondió con código {response.status_code}")
            return
    except requests.exceptions.ConnectionError:
        print("   ❌ ERROR: El servidor no está corriendo")
        print("   💡 Solución: Ejecuta 'python app.py' en otra terminal")
        return
    except Exception as e:
        print(f"   ❌ ERROR: {e}")
        return
    
    # 2. Obtener el último escaneo
    print("\n2. Verificando escaneos disponibles...")
    reports_dir = 'reports'
    scan_dirs = [d for d in os.listdir(reports_dir) 
                 if d.startswith('scan_') and os.path.isdir(os.path.join(reports_dir, d))]
    
    if not scan_dirs:
        print("   ❌ No hay escaneos disponibles")
        print("   💡 Solución: Ejecuta 'python run.py https://example.com'")
        return
    
    latest_scan = sorted(scan_dirs)[-1]
    print(f"   ✅ Último escaneo: {latest_scan}")
    
    # 3. Verificar que crawl_tree.json existe
    print("\n3. Verificando crawl_tree.json...")
    crawl_tree_path = os.path.join(reports_dir, latest_scan, 'crawl_tree.json')
    
    if not os.path.exists(crawl_tree_path):
        print(f"   ❌ Archivo no encontrado: {crawl_tree_path}")
        print("   💡 Solución: Ejecuta un escaneo sin --no-crawl")
        return
    
    print(f"   ✅ Archivo existe: {crawl_tree_path}")
    
    # 4. Verificar que el JSON es válido
    print("\n4. Verificando que el JSON es válido...")
    try:
        with open(crawl_tree_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        print(f"   ✅ JSON válido con {len(data)} nodos raíz")
    except json.JSONDecodeError as e:
        print(f"   ❌ JSON inválido: {e}")
        return
    
    # 5. Probar el endpoint de la API
    print("\n5. Probando endpoint de la API...")
    api_url = f"{base_url}/api/crawl_tree/{latest_scan}"
    print(f"   URL: {api_url}")
    
    try:
        response = requests.get(api_url, timeout=5)
        if response.status_code == 200:
            api_data = response.json()
            print(f"   ✅ API respondió correctamente con {len(api_data)} nodos")
        else:
            print(f"   ❌ API respondió con código {response.status_code}")
            print(f"   Respuesta: {response.text[:200]}")
            return
    except Exception as e:
        print(f"   ❌ Error llamando a la API: {e}")
        return
    
    # 6. Probar la página del árbol de crawling
    print("\n6. Probando página del árbol de crawling...")
    tree_url = f"{base_url}/crawl_tree/{latest_scan}"
    print(f"   URL: {tree_url}")
    
    try:
        response = requests.get(tree_url, timeout=5)
        if response.status_code == 200:
            print("   ✅ Página del árbol cargó correctamente")
        else:
            print(f"   ❌ Página respondió con código {response.status_code}")
            return
    except Exception as e:
        print(f"   ❌ Error cargando la página: {e}")
        return
    
    # 7. URLs para acceder
    print("\n" + "="*60)
    print("✅ TODAS LAS PRUEBAS PASARON")
    print("="*60)
    print("\n📊 Accede a los reportes en:")
    print(f"\n   Página principal:")
    print(f"   {base_url}/")
    print(f"\n   Árbol de crawling:")
    print(f"   {tree_url}")
    print(f"\n   Reporte de vulnerabilidades:")
    print(f"   {base_url}/reports/{latest_scan}/vulnerability_report.html")
    print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    test_flask_server()
