"""
Ejemplo de uso del HTTPClient centralizado.
Demuestra caching, session pooling y comparación de respuestas.
"""
from core.http_client import HTTPClient


def main():
    # Configuración
    config = {
        'timeout': 10,
        'user_agent': 'Mozilla/5.0 Security Scanner'
    }
    
    # Crear cliente HTTP (reutiliza conexiones)
    http_client = HTTPClient(config)
    
    # Ejemplo 1: Request simple
    print("=== Ejemplo 1: Request Simple ===")
    url = "http://testphp.vulnweb.com/"
    response = http_client.make_request(url)
    
    if response:
        print(f"Status: {response.status_code}")
        print(f"Longitud: {len(response.text)} bytes")
    
    # Ejemplo 2: Baseline con caching
    print("\n=== Ejemplo 2: Baseline con Caching ===")
    
    # Primera llamada - hace request real
    print("Primera llamada (request real)...")
    baseline1 = http_client.get_baseline_response(url)
    print(f"Baseline obtenido: {baseline1['length']} bytes")
    
    # Segunda llamada - usa cache
    print("Segunda llamada (desde cache)...")
    baseline2 = http_client.get_baseline_response(url)
    print(f"Baseline desde cache: {baseline2['length']} bytes")
    print(f"¿Mismo objeto? {baseline1 is baseline2}")
    
    # Ejemplo 3: Comparación de respuestas
    print("\n=== Ejemplo 3: Comparación de Respuestas ===")
    
    # Simular respuesta de prueba con payload
    test_url = url + "?search=<script>alert('XSS')</script>"
    test_response_obj = http_client.make_request(test_url)
    
    if test_response_obj:
        test_response = {
            'status_code': test_response_obj.status_code,
            'content': test_response_obj.text,
            'length': len(test_response_obj.text),
            'hash': None
        }
        
        # Comparar con baseline
        comparison = http_client.compare_responses(baseline1, test_response)
        
        print(f"Diferencia de status code: {comparison['status_code_diff']}")
        print(f"Diferencia de longitud: {comparison['length_diff']} bytes")
        print(f"Similitud: {comparison['similarity']:.2%}")
        print(f"¿Diferencia significativa? {comparison['significant_diff']}")
        print(f"Confianza: {comparison['confidence']}%")
    
    # Ejemplo 4: POST request
    print("\n=== Ejemplo 4: POST Request ===")
    
    post_url = "http://testphp.vulnweb.com/login.php"
    post_data = {
        'uname': 'test',
        'pass': 'test'
    }
    
    response = http_client.make_request(post_url, method='POST', data=post_data)
    if response:
        print(f"POST Status: {response.status_code}")
    
    # Ejemplo 5: Limpiar cache
    print("\n=== Ejemplo 5: Limpiar Cache ===")
    print(f"Cache antes: {len(http_client.baseline_cache)} entradas")
    http_client.clear_cache()
    print(f"Cache después: {len(http_client.baseline_cache)} entradas")


if __name__ == "__main__":
    main()
