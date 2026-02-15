"""
Integración con sqlmap (https://sqlmap.org/)
Permite ejecutar sqlmap en modo batch y parsear resultados JSON.
"""
import subprocess
import json
from core.logger import get_logger

class SqlmapRunner:
    def __init__(self, config):
        self.config = config
        self.logger = get_logger("sqlmap")
        self.sqlmap_path = config.get("sqlmap_path", "sqlmap.py")  # Asume en PATH o ruta

    def _find_sqlmap_exec(self):
        import shutil
        import os
        import platform
        is_windows = platform.system().lower().startswith("win")
        bin_name = "sqlmap.exe" if is_windows else "sqlmap.py"
        search_paths = [
            shutil.which(self.sqlmap_path),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', bin_name)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'sqlmap', bin_name)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'windows' if is_windows else 'linux', bin_name)),
        ]
        for path in search_paths:
            if path and os.path.isfile(path):
                return path, bin_name
        return None, bin_name

    def run(self, target, data=None, extra_args=None):
        """Ejecuta sqlmap sobre el objetivo y retorna hallazgos como lista."""
        sqlmap_exec, bin_name = self._find_sqlmap_exec()
        if not sqlmap_exec:
            self.logger.error(
                f"sqlmap no está instalado o no se encuentra en el PATH. "
                f"Descárgalo de https://github.com/sqlmapproject/sqlmap y colócalo en el PATH, en la raíz del proyecto como {bin_name}, en tools/sqlmap/ o en windows/ o linux/. "
                f"También puedes configurar sqlmap_path en config."
            )
            return []
        # Si es .py, usar python para ejecutarlo
        if sqlmap_exec.endswith('.py'):
            cmd = ["python", sqlmap_exec, "-u", target, "--batch", "--output-dir=tmp_sqlmap", "--risk=3", "--level=5", "--random-agent", "--flush-session", "--answers=follow=Y"]
        else:
            cmd = [sqlmap_exec, "-u", target, "--batch", "--output-dir=tmp_sqlmap", "--risk=3", "--level=5", "--random-agent", "--flush-session", "--answers=follow=Y"]
        if data:
            cmd += ["--data", data]
        if extra_args:
            cmd += extra_args
        cmd += ["--output-format=JSON"]
        self.logger.info(f"Ejecutando sqlmap: {' '.join(cmd)}")
        try:
            import subprocess
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            findings = self._parse_sqlmap_output()
            self.logger.info(f"sqlmap hallazgos: {len(findings)}")
            return findings
        except Exception as e:
            self.logger.error(f"Error ejecutando sqlmap: {e}")
            return []

    def _parse_sqlmap_output(self):
        # Busca archivos JSON en tmp_sqlmap y los parsea
        import os
        findings = []
        outdir = "tmp_sqlmap"
        if not os.path.isdir(outdir):
            return findings
        for root, _, files in os.walk(outdir):
            for f in files:
                if f.endswith(".json"):
                    try:
                        with open(os.path.join(root, f), "r", encoding="utf-8") as j:
                            findings.append(json.load(j))
                    except Exception:
                        continue
        return findings
