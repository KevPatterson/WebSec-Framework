"""
Integración con OWASP ZAP (https://www.zaproxy.org/)
Permite lanzar escaneos en modo headless y parsear resultados JSON.
"""
import subprocess
import json
from core.logger import get_logger

class ZapRunner:
    def __init__(self, config):
        self.config = config
        self.logger = get_logger("zap")
        self.zap_path = config.get("zap_path", "zap.sh")  # Asume en PATH o ruta

    def _find_zap_exec(self):
        import shutil
        import os
        import platform
        is_windows = platform.system().lower().startswith("win")
        bin_name = "zap.exe" if is_windows else "zap.sh"
        search_paths = [
            shutil.which(self.zap_path),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', bin_name)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'zap', bin_name)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'windows' if is_windows else 'linux', bin_name)),
        ]
        for path in search_paths:
            if path and os.path.isfile(path):
                return path, bin_name
        return None, bin_name

    def run(self, target, extra_args=None):
        """Ejecuta ZAP en modo headless sobre el objetivo y retorna hallazgos como lista."""
        zap_exec, bin_name = self._find_zap_exec()
        if not zap_exec:
            self.logger.error(
                f"ZAP no está instalado o no se encuentra en el PATH. "
                f"Descárgalo de https://www.zaproxy.org/download/ y colócalo en el PATH, en la raíz del proyecto como {bin_name}, en tools/zap/ o en windows/ o linux/. "
                f"También puedes configurar zap_path en config."
            )
            return []
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        cmd = [zap_exec, "-cmd", "-quickurl", target, "-quickout", f"zap_report_{timestamp}.json"]
        if extra_args:
            cmd += extra_args
        self.logger.info(f"Ejecutando ZAP: {' '.join(cmd)}")
        try:
            import subprocess
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            findings = self._parse_zap_output()
            self.logger.info(f"ZAP hallazgos: {len(findings)}")
            return findings
        except Exception as e:
            self.logger.error(f"Error ejecutando ZAP: {e}")
            return []

    def _parse_zap_output(self):
        # Lee zap_report.json generado
        try:
            with open("zap_report.json", "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
