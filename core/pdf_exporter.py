"""
Exportador de reportes HTML a PDF usando wkhtmltopdf.
"""

import os
import subprocess
import platform
from core.logger import get_logger


class PDFExporter:
    """Exporta reportes HTML a PDF profesionales."""
    
    def __init__(self):
        self.logger = get_logger("pdf_exporter")
        self.wkhtmltopdf_path = self._find_wkhtmltopdf()
    
    def _find_wkhtmltopdf(self):
        """Encuentra el ejecutable de wkhtmltopdf."""
        system = platform.system()
        
        # Rutas posibles
        possible_paths = []
        
        if system == "Windows":
            possible_paths = [
                os.path.join("tools", "wkhtmltopdf", "wkhtmltopdf.exe"),
                "wkhtmltopdf.exe",
                r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe",
                r"C:\Program Files (x86)\wkhtmltopdf\bin\wkhtmltopdf.exe"
            ]
        else:  # Linux/Mac
            possible_paths = [
                "wkhtmltopdf",
                "/usr/bin/wkhtmltopdf",
                "/usr/local/bin/wkhtmltopdf"
            ]
        
        # Buscar en las rutas
        for path in possible_paths:
            if os.path.exists(path):
                self.logger.info(f"wkhtmltopdf encontrado en: {path}")
                return path
        
        # Intentar encontrar en PATH
        try:
            result = subprocess.run(
                ["wkhtmltopdf", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                self.logger.info("wkhtmltopdf encontrado en PATH")
                return "wkhtmltopdf"
        except:
            pass
        
        self.logger.warning("wkhtmltopdf no encontrado. La exportación PDF no estará disponible.")
        return None
    
    def is_available(self):
        """Verifica si wkhtmltopdf está disponible."""
        return self.wkhtmltopdf_path is not None
    
    def export(self, html_path, pdf_path, options=None):
        """
        Exporta un archivo HTML a PDF.
        
        Args:
            html_path: Ruta del archivo HTML
            pdf_path: Ruta donde guardar el PDF
            options: Dict con opciones adicionales
        
        Returns:
            bool: True si la exportación fue exitosa
        """
        if not self.is_available():
            self.logger.error("wkhtmltopdf no está disponible")
            return False
        
        if not os.path.exists(html_path):
            self.logger.error(f"Archivo HTML no encontrado: {html_path}")
            return False
        
        try:
            # Opciones por defecto
            default_options = {
                "page-size": "A4",
                "margin-top": "10mm",
                "margin-right": "10mm",
                "margin-bottom": "10mm",
                "margin-left": "10mm",
                "encoding": "UTF-8",
                "enable-local-file-access": None,
                "print-media-type": None,
                "no-stop-slow-scripts": None,
                "javascript-delay": "1000"
            }
            
            # Combinar con opciones del usuario
            if options:
                default_options.update(options)
            
            # Construir comando
            cmd = [self.wkhtmltopdf_path]
            
            for key, value in default_options.items():
                if value is None:
                    cmd.append(f"--{key}")
                else:
                    cmd.extend([f"--{key}", str(value)])
            
            cmd.extend([html_path, pdf_path])
            
            self.logger.info(f"Generando PDF: {pdf_path}")
            
            # Ejecutar wkhtmltopdf
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                if os.path.exists(pdf_path):
                    file_size = os.path.getsize(pdf_path)
                    self.logger.info(f"PDF generado exitosamente: {pdf_path} ({file_size} bytes)")
                    return True
                else:
                    self.logger.error("PDF no se generó correctamente")
                    return False
            else:
                self.logger.error(f"Error al generar PDF: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Timeout al generar PDF")
            return False
        except Exception as e:
            self.logger.error(f"Error inesperado al generar PDF: {e}")
            return False
    
    def get_installation_instructions(self):
        """Retorna instrucciones de instalación según el sistema operativo."""
        system = platform.system()
        
        if system == "Windows":
            return """
Para instalar wkhtmltopdf en Windows:
1. Descarga desde: https://wkhtmltopdf.org/downloads.html
2. Instala el ejecutable
3. O copia wkhtmltopdf.exe a la carpeta tools/wkhtmltopdf/
"""
        elif system == "Linux":
            return """
Para instalar wkhtmltopdf en Linux:
Ubuntu/Debian: sudo apt-get install wkhtmltopdf
Fedora/RHEL: sudo yum install wkhtmltopdf
Arch: sudo pacman -S wkhtmltopdf
"""
        else:  # macOS
            return """
Para instalar wkhtmltopdf en macOS:
brew install wkhtmltopdf
"""
