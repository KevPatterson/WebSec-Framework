"""
Clase base mejorada para módulos de vulnerabilidades.
Elimina duplicación de código común en todos los módulos.
"""
import os
import json
from abc import ABC, abstractmethod
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from core.logger import get_logger
from core.http_client import HTTPClient
from core.payload_manager import PayloadManager
from datetime import datetime


class EnhancedVulnerabilityModule(ABC):
    """
    Clase base mejorada con funcionalidad común:
    - Descubrimiento de puntos de inyección
    - Manejo de requests HTTP
    - Carga de payloads
    - Exportación de resultados
    - Extracción de evidencia
    """
    
    def __init__(self, config):
        self.config = config
        self.target_url = config.get("target_url")
        self.findings = []
        self.tested_params = set()
        
        # Configuración compartida
        self.scan_timestamp = config.get("scan_timestamp", datetime.now().strftime("%Y%m%d_%H%M%S"))
        self.report_dir = config.get("report_dir", f"reports/scan_{self.scan_timestamp}")
        self.timeout = config.get("timeout", 10)
        
        # Logger específico del módulo
        module_name = self.__class__.__name__.replace('Module', '').lower()
        self.logger = get_logger(f"{module_name}_module")
        
        # Cliente HTTP compartido
        self.http_client = HTTPClient(config)
        
        # Gestor de payloads compartido
        self.payload_manager = PayloadManager(config)
    
    @abstractmethod
    def scan(self):
        """Ejecuta el escaneo de la vulnerabilidad."""
        pass
    
    def get_results(self):
        """Devuelve los hallazgos encontrados."""
        return self.findings
    
    def _discover_injection_points(self, keywords=None):
        """
        Descubre puntos de inyección (parámetros GET y formularios POST).
        
        Args:
            keywords: Lista de palabras clave para filtrar parámetros (opcional)
            
        Returns:
            Lista de dicts con puntos de inyección
        """
        injection_points = []
        
        try:
            # 1. Parámetros GET de la URL
            parsed = urlparse(self.target_url)
            params = parse_qs(parsed.query)
            
            for param, values in params.items():
                if keywords and not any(kw in param.lower() for kw in keywords):
                    continue
                
                injection_points.append({
                    'type': 'GET',
                    'url': self.target_url,
                    'parameter': param,
                    'original_value': values[0] if values else ''
                })
            
            # 2. Formularios POST
            response = self.http_client.make_request(self.target_url)
            
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    action = form.get('action', '')
                    method = form.get('method', 'GET').upper()
                    form_url = urljoin(self.target_url, action) if action else self.target_url
                    
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    
                    for input_field in inputs:
                        input_name = input_field.get('name')
                        input_type = input_field.get('type', 'text')
                        
                        if not input_name:
                            continue
                        
                        if keywords and not any(kw in input_name.lower() for kw in keywords):
                            continue
                        
                        injection_points.append({
                            'type': method,
                            'url': form_url,
                            'parameter': input_name,
                            'input_type': input_type,
                            'original_value': input_field.get('value', '')
                        })
            
            self.logger.info(f"Descubiertos {len(injection_points)} puntos de inyección")
            
        except Exception as e:
            self.logger.error(f"Error descubriendo puntos de inyección: {e}")
        
        return injection_points
    
    def _make_request(self, url, method='GET', data=None, params=None, headers=None):
        """
        Wrapper para hacer requests HTTP.
        
        Args:
            url: URL objetivo
            method: Método HTTP
            data: Datos POST
            params: Parámetros GET
            headers: Headers adicionales
            
        Returns:
            Response object o None
        """
        return self.http_client.make_request(url, method, data, params, headers)
    
    def _get_baseline_response(self, url, method='GET', data=None):
        """
        Obtiene respuesta baseline (sin payload).
        
        Args:
            url: URL objetivo
            method: Método HTTP
            data: Datos POST
            
        Returns:
            dict con metadata de respuesta
        """
        return self.http_client.get_baseline_response(url, method, data)
    
    def _load_payloads(self, vuln_type, max_count=None):
        """
        Carga payloads desde el gestor centralizado.
        
        Args:
            vuln_type: Tipo de vulnerabilidad (xss, sqli, lfi, etc.)
            max_count: Número máximo de payloads
            
        Returns:
            Lista de payloads
        """
        max_payloads = max_count or self.config.get(f'max_{vuln_type}_payloads', 20)
        return self.payload_manager.get_payloads(vuln_type, max_payloads)
    
    def _export_results(self, filename=None):
        """
        Exporta resultados a JSON.
        
        Args:
            filename: Nombre del archivo (opcional)
            
        Returns:
            bool indicando éxito
        """
        if not self.findings:
            self.logger.info("No hay hallazgos para exportar")
            return False
        
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            
            if not filename:
                module_name = self.__class__.__name__.replace('Module', '').lower()
                filename = f"{module_name}_findings.json"
            
            output_path = os.path.join(self.report_dir, filename)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.findings, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Resultados exportados a: {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exportando resultados: {e}")
            return False
    
    def _get_context_snippet(self, content, search_text, context_size=100):
        """
        Extrae snippet de contexto alrededor de un texto.
        
        Args:
            content: Contenido completo
            search_text: Texto a buscar
            context_size: Tamaño del contexto en caracteres
            
        Returns:
            str con snippet de contexto
        """
        if not content or not search_text:
            return ""
        
        try:
            index = content.find(search_text)
            if index == -1:
                return content[:context_size * 2]
            
            start = max(0, index - context_size)
            end = min(len(content), index + len(search_text) + context_size)
            
            snippet = content[start:end]
            
            if start > 0:
                snippet = "..." + snippet
            if end < len(content):
                snippet = snippet + "..."
            
            return snippet
            
        except Exception:
            return content[:context_size * 2]
    
    def _add_finding(self, vulnerability, severity, url, details=None, payload=None):
        """
        Añade un hallazgo a la lista de resultados.
        
        Args:
            vulnerability: Nombre de la vulnerabilidad
            severity: Severidad (critical, high, medium, low, info)
            url: URL afectada
            details: Detalles adicionales (dict)
            payload: Payload usado
        """
        finding = {
            'vulnerability': vulnerability,
            'severity': severity,
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'module': self.__class__.__name__
        }
        
        if details:
            finding['details'] = details
        
        if payload:
            finding['payload'] = payload
        
        self.findings.append(finding)
        self.logger.info(f"Hallazgo añadido: {vulnerability} en {url}")
