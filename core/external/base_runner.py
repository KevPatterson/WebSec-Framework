"""
Interfaz base para runners de herramientas externas.
Unifica el manejo de subprocess, errores y resultados.
"""
import os
import subprocess
import shutil
import platform
from abc import ABC, abstractmethod
from core.logger import get_logger


class BaseExternalRunner(ABC):
    """
    Clase base abstracta para runners de herramientas externas.
    Proporciona funcionalidad común para Nmap, Nuclei, SQLMap, ZAP, etc.
    """
    
    DEFAULT_TIMEOUT = 300
    
    def __init__(self, config):
        self.config = config
        self.tool_name = self.__class__.__name__.replace('Runner', '').lower()
        self.logger = get_logger(f"{self.tool_name}_runner")
        self.timeout = config.get(f"{self.tool_name}_timeout", self.DEFAULT_TIMEOUT)
    
    @abstractmethod
    def is_available(self):
        """Verifica si la herramienta está disponible."""
        pass
    
    @abstractmethod
    def run(self, target, **kwargs):
        """Ejecuta la herramienta sobre el objetivo."""
        pass
    
    @abstractmethod
    def parse_results(self, output):
        """Parsea la salida de la herramienta."""
        pass
    
    def find_executable(self, binary_name, search_paths=None):
        """
        Busca el ejecutable de la herramienta.
        
        Args:
            binary_name: Nombre del binario (ej: 'nmap', 'nuclei')
            search_paths: Rutas adicionales donde buscar
            
        Returns:
            Ruta al ejecutable o None
        """
        is_windows = platform.system().lower().startswith("win")
        
        if is_windows and not binary_name.endswith('.exe'):
            binary_name += '.exe'
        
        # Buscar en PATH
        path_exec = shutil.which(binary_name)
        if path_exec and os.path.isfile(path_exec):
            return path_exec
        
        # Buscar en rutas personalizadas
        if not search_paths:
            search_paths = [
                os.path.join(os.path.dirname(__file__), '..', '..', binary_name),
                os.path.join(os.path.dirname(__file__), '..', '..', 'tools', self.tool_name, binary_name),
                os.path.join(os.path.dirname(__file__), '..', '..', 'tools', self.tool_name, 
                            'windows' if is_windows else 'linux', binary_name),
            ]
        
        for path in search_paths:
            abs_path = os.path.abspath(path)
            if os.path.isfile(abs_path):
                return abs_path
        
        return None
    
    def execute_command(self, cmd, timeout=None, capture_output=True):
        """
        Ejecuta un comando con manejo de errores unificado.
        
        Args:
            cmd: Lista con comando y argumentos
            timeout: Timeout en segundos
            capture_output: Capturar stdout/stderr
            
        Returns:
            subprocess.CompletedProcess o None si falla
        """
        real_timeout = timeout or self.timeout
        
        try:
            self.logger.info(f"Ejecutando: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=real_timeout
            )
            
            if result.returncode != 0 and result.stderr:
                self.logger.warning(f"Stderr: {result.stderr.strip()}")
            
            return result
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout tras {real_timeout}s ejecutando {self.tool_name}")
            return None
        except FileNotFoundError:
            self.logger.error(f"Ejecutable no encontrado: {cmd[0]}")
            return None
        except Exception as e:
            self.logger.error(f"Error ejecutando {self.tool_name}: {e}")
            return None
    
    def export_results(self, results, output_file):
        """
        Exporta resultados a archivo JSON.
        
        Args:
            results: Resultados a exportar
            output_file: Ruta del archivo de salida
            
        Returns:
            bool indicando éxito
        """
        if not results:
            self.logger.warning("No hay resultados para exportar")
            return False
        
        try:
            import json
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Resultados exportados a: {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exportando resultados: {e}")
            return False
    
    def validate_installation(self):
        """
        Valida que la herramienta esté correctamente instalada.
        
        Returns:
            tuple (bool, str) - (disponible, mensaje)
        """
        if not self.is_available():
            return False, f"{self.tool_name} no está disponible"
        
        return True, f"{self.tool_name} está disponible"
