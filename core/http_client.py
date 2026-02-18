"""
Cliente HTTP unificado con caching y manejo de errores.
Elimina duplicación de requests en todos los módulos.
"""
import requests
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from core.logger import get_logger


class HTTPClient:
    """
    Cliente HTTP centralizado con:
    - Session pooling para reutilizar conexiones
    - Caching de respuestas baseline
    - Manejo unificado de errores
    - Comparación de respuestas
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = get_logger("http_client")
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': config.get('user_agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        })
        
        # Cache de respuestas baseline
        self.baseline_cache = {}
        self.timeout = config.get('timeout', 10)
        self.max_redirects = config.get('max_redirects', 5)
    
    def make_request(self, url, method='GET', data=None, params=None, headers=None, 
                     allow_redirects=True, timeout=None):
        """
        Realiza request HTTP con manejo de errores unificado.
        
        Args:
            url: URL objetivo
            method: GET, POST, OPTIONS, etc.
            data: Datos POST
            params: Parámetros GET
            headers: Headers adicionales
            allow_redirects: Seguir redirects
            timeout: Timeout personalizado
            
        Returns:
            Response object o None si falla
        """
        try:
            req_timeout = timeout or self.timeout
            req_headers = self.session.headers.copy()
            if headers:
                req_headers.update(headers)
            
            if method.upper() == 'GET':
                response = self.session.get(
                    url, 
                    params=params,
                    headers=req_headers,
                    timeout=req_timeout,
                    allow_redirects=allow_redirects
                )
            elif method.upper() == 'POST':
                response = self.session.post(
                    url,
                    data=data,
                    params=params,
                    headers=req_headers,
                    timeout=req_timeout,
                    allow_redirects=allow_redirects
                )
            elif method.upper() == 'OPTIONS':
                response = self.session.options(
                    url,
                    headers=req_headers,
                    timeout=req_timeout
                )
            else:
                response = self.session.request(
                    method,
                    url,
                    data=data,
                    params=params,
                    headers=req_headers,
                    timeout=req_timeout,
                    allow_redirects=allow_redirects
                )
            
            return response
            
        except requests.exceptions.Timeout:
            self.logger.debug(f"Timeout en request a {url}")
            return None
        except requests.exceptions.ConnectionError:
            self.logger.debug(f"Error de conexión a {url}")
            return None
        except requests.exceptions.TooManyRedirects:
            self.logger.debug(f"Demasiados redirects en {url}")
            return None
        except Exception as e:
            self.logger.debug(f"Error en request a {url}: {e}")
            return None
    
    def get_baseline_response(self, url, method='GET', data=None, use_cache=True):
        """
        Obtiene respuesta baseline (sin payload) con caching.
        
        Args:
            url: URL objetivo
            method: Método HTTP
            data: Datos POST
            use_cache: Usar cache
            
        Returns:
            dict con metadata de respuesta
        """
        cache_key = self._get_cache_key(url, method, data)
        
        if use_cache and cache_key in self.baseline_cache:
            return self.baseline_cache[cache_key]
        
        response = self.make_request(url, method=method, data=data)
        
        if not response:
            return None
        
        baseline = {
            'status_code': response.status_code,
            'content': response.text,
            'length': len(response.text),
            'headers': dict(response.headers),
            'response_time': response.elapsed.total_seconds(),
            'hash': hashlib.md5(response.text.encode()).hexdigest()
        }
        
        if use_cache:
            self.baseline_cache[cache_key] = baseline
        
        return baseline
    
    def compare_responses(self, baseline, test_response):
        """
        Compara respuesta baseline con respuesta de prueba.
        
        Args:
            baseline: dict de respuesta baseline
            test_response: dict de respuesta de prueba
            
        Returns:
            dict con análisis de diferencias
        """
        if not baseline or not test_response:
            return {'significant_diff': False, 'confidence': 0}
        
        import difflib
        
        analysis = {
            'status_code_diff': baseline['status_code'] != test_response.get('status_code', baseline['status_code']),
            'length_diff': abs(baseline['length'] - test_response.get('length', baseline['length'])),
            'length_diff_percent': 0,
            'hash_diff': baseline['hash'] != test_response.get('hash', baseline['hash']),
            'similarity': 0,
            'significant_diff': False,
            'confidence': 0
        }
        
        if baseline['length'] > 0:
            analysis['length_diff_percent'] = (analysis['length_diff'] / baseline['length']) * 100
        
        if baseline['content'] and test_response.get('content'):
            matcher = difflib.SequenceMatcher(None, baseline['content'], test_response['content'])
            analysis['similarity'] = matcher.ratio()
        
        # Diferencia significativa si hay cambios importantes
        analysis['significant_diff'] = (
            analysis['status_code_diff'] or
            analysis['length_diff'] > 100 or
            analysis['similarity'] < 0.85
        )
        
        # Calcular confianza
        confidence = 0
        if analysis['status_code_diff']:
            confidence += 30
        if analysis['length_diff'] > 100:
            confidence += 25
        if analysis['similarity'] < 0.85:
            confidence += 25
        if analysis['hash_diff']:
            confidence += 20
        
        analysis['confidence'] = min(confidence, 100)
        
        return analysis
    
    def _get_cache_key(self, url, method, data):
        """Genera clave de cache."""
        key_parts = [url, method]
        if data:
            key_parts.append(str(sorted(data.items())))
        return hashlib.md5('|'.join(key_parts).encode()).hexdigest()
    
    def clear_cache(self):
        """Limpia cache de baselines."""
        self.baseline_cache.clear()
        self.logger.debug("Cache de baselines limpiado")
