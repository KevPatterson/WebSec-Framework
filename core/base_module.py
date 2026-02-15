"""
Interfaz base para módulos de vulnerabilidades.
Define la estructura mínima y contratos para todos los módulos.
"""
from abc import ABC, abstractmethod

class VulnerabilityModule(ABC):
    def __init__(self, config):
        self.config = config

    @abstractmethod
    def scan(self):
        """Ejecuta el escaneo de la vulnerabilidad."""
        pass

    @abstractmethod
    def get_results(self):
        """Devuelve los hallazgos encontrados por el módulo."""
        pass