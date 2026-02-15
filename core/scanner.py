"""
Módulo de escaneo de vulnerabilidades. Orquesta módulos independientes.
"""

class Scanner:
    def __init__(self, target_url, config):
        self.target_url = target_url
        self.config = config
        self.modules = []  # Lista de módulos de vulnerabilidades

    def register_module(self, module):
        self.modules.append(module)

    def run(self):
        """Ejecuta todos los módulos de escaneo registrados."""
        for module in self.modules:
            module.scan()
