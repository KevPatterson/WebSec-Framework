"""
Ejemplo de módulo optimizado usando EnhancedVulnerabilityModule.
Demuestra cómo crear un módulo con menos código duplicado.
"""
from core.enhanced_base_module import EnhancedVulnerabilityModule


class OptimizedXSSModule(EnhancedVulnerabilityModule):
    """
    Ejemplo de módulo XSS optimizado.
    Hereda toda la funcionalidad común de EnhancedVulnerabilityModule.
    """
    
    def __init__(self, config):
        super().__init__(config)
        # HTTPClient, PayloadManager, logger ya están disponibles
        # target_url, findings, report_dir ya están configurados
        
        # Cargar payloads desde PayloadManager (cargados una sola vez)
        self.payloads = self._load_payloads('xss', max_count=20)
        
        # Configuración específica del módulo
        self.max_tests_per_param = config.get('max_xss_tests', 10)
    
    def scan(self):
        """Ejecuta el escaneo de XSS."""
        self.logger.info(f"Iniciando escaneo XSS optimizado en: {self.target_url}")
        
        # 1. Descubrir puntos de inyección (método heredado)
        injection_points = self._discover_injection_points()
        
        if not injection_points:
            self.logger.warning("No se encontraron puntos de inyección")
            return
        
        self.logger.info(f"Encontrados {len(injection_points)} puntos de inyección")
        
        # 2. Obtener baseline (con caching automático)
        baseline = self._get_baseline_response(self.target_url)
        
        # 3. Probar payloads en cada punto de inyección
        for point in injection_points[:5]:  # Limitar para ejemplo
            self._test_injection_point(point, baseline)
        
        # 4. Exportar resultados (método heredado)
        self._export_results()
        
        self.logger.info(f"Escaneo completado. Hallazgos: {len(self.findings)}")
    
    def _test_injection_point(self, point, baseline):
        """Prueba un punto de inyección con payloads XSS."""
        url = point['url']
        param = point['parameter']
        method = point['type']
        
        # Evitar duplicados
        test_key = f"{url}:{param}"
        if test_key in self.tested_params:
            return
        self.tested_params.add(test_key)
        
        self.logger.debug(f"Probando parámetro: {param} en {url}")
        
        # Probar cada payload
        for payload in self.payloads[:self.max_tests_per_param]:
            # Hacer request con payload (método heredado)
            if method == 'GET':
                response = self._make_request(url, params={param: payload})
            else:
                response = self._make_request(url, method='POST', data={param: payload})
            
            if not response:
                continue
            
            # Detectar XSS
            if self._detect_xss(payload, response.text):
                # Añadir hallazgo (método heredado)
                self._add_finding(
                    vulnerability='Cross-Site Scripting (XSS)',
                    severity='high',
                    url=url,
                    payload=payload,
                    details={
                        'parameter': param,
                        'method': method,
                        'type': 'reflected',
                        'evidence': self._get_context_snippet(response.text, payload),
                        'status_code': response.status_code
                    }
                )
                
                self.logger.info(f"XSS detectado en {param}")
                break  # Un payload exitoso es suficiente
    
    def _detect_xss(self, payload, response_content):
        """Detecta si el payload XSS fue exitoso."""
        # Verificar si el payload está reflejado sin sanitización
        if payload in response_content:
            # Verificar que no esté sanitizado
            sanitized = payload.replace('<', '&lt;').replace('>', '&gt;')
            if sanitized not in response_content:
                return True
        
        return False


# Ejemplo de uso
if __name__ == "__main__":
    config = {
        'target_url': 'http://testphp.vulnweb.com/search.php?test=query',
        'timeout': 10,
        'max_xss_payloads': 15,
        'max_xss_tests': 5
    }
    
    module = OptimizedXSSModule(config)
    module.scan()
    
    # Obtener resultados
    findings = module.get_results()
    print(f"\nHallazgos encontrados: {len(findings)}")
    for finding in findings:
        print(f"- {finding['vulnerability']} en {finding['url']}")
