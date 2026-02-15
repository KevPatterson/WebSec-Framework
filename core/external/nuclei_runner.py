"""
Integración profesional con Nuclei (https://nuclei.projectdiscovery.io/)
Permite ejecutar plantillas personalizadas, parsear resultados JSON y manejar errores de forma robusta.
"""
import os
import platform
import shutil
import subprocess
import json
import stat
from core.logger import get_logger

class NucleiRunner:
    def get_templates_path(self):
        """
        Devuelve la ruta de templates personalizada o la ruta por defecto del framework.
        """
        if self.templates:
            return self.templates
        # Ruta por defecto del framework
        base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'nuclei-templates'))
        if not os.path.exists(base):
            os.makedirs(base, exist_ok=True)
        return base

    def update_templates(self):
        """
        Actualiza los templates de Nuclei usando el binario correspondiente.
        """
        nuclei_exec, _ = self._find_nuclei_exec()
        if not nuclei_exec:
            self.logger.error("No se encontró el binario de Nuclei para actualizar templates.")
            return False
        templates_path = self.get_templates_path()
        cmd = [nuclei_exec, "-update-templates", "-ut-dir", templates_path]
        self.logger.info(f"Actualizando templates de Nuclei en {templates_path}...")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if result.returncode == 0:
                self.logger.info("Templates de Nuclei actualizados correctamente.")
                return True
            else:
                self.logger.error(f"Error actualizando templates: {result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"Error ejecutando actualización de templates: {e}")
            return False
    """
    Clase para orquestar la ejecución de Nuclei desde el framework.
    - Busca el binario multiplataforma en ubicaciones estándar.
    - Permite especificar plantillas personalizadas.
    - Soporta timeout configurable y argumentos extra.
    - Valida permisos de ejecución y muestra mensajes claros.
    """
    DEFAULT_TIMEOUT = 120

    def __init__(self, config):
        self.config = config
        self.logger = get_logger("nuclei")
        self.nuclei_path = config.get("nuclei_path", "nuclei")  # PATH o nombre
        self.templates = config.get("nuclei_templates", None)
        self.timeout = config.get("nuclei_timeout", self.DEFAULT_TIMEOUT)

    def _find_nuclei_exec(self):
        is_windows = platform.system().lower().startswith("win")
        bin_name = "nuclei.exe" if is_windows else "nuclei"
        # Rutas adicionales para soporte multiplataforma profesional
        search_paths = [
            shutil.which(self.nuclei_path),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', bin_name)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'nuclei', bin_name)),
            os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'tools', 'nuclei', 'windows' if is_windows else 'linux', bin_name)),
        ]
        for path in search_paths:
            if path and os.path.isfile(path):
                # Validar permisos de ejecución en Linux
                if not is_windows:
                    try:
                        st = os.stat(path)
                        if not (st.st_mode & stat.S_IXUSR):
                            self.logger.warning(f"El binario {path} no es ejecutable. Corrigiendo permisos...")
                            os.chmod(path, st.st_mode | stat.S_IXUSR)
                    except Exception as e:
                        self.logger.warning(f"No se pudo validar permisos de ejecución para {path}: {e}")
                return path, bin_name
        return None, bin_name

    def run(self, target, extra_args=None, templates=None, timeout=None, severity=None, tags=None, cves=None, include_categories=None, url_list=None, headers=None, cookies=None, rate_limit=None, proxy=None, threads=None, output_file=None):
        """
        Ejecuta Nuclei sobre uno o varios objetivos y retorna hallazgos como lista de dicts.
        :param target: URL objetivo (str) o None si se usa url_list
        :param url_list: lista de URLs o ruta a archivo de URLs (opcional)
        :param extra_args: lista de argumentos extra para Nuclei
        :param templates: ruta a plantillas personalizadas (opcional)
        :param timeout: timeout de ejecución en segundos (opcional)
        :param severity: lista o str de severidades (critical, high, medium, low, info)
        :param tags: lista o str de tags (ej: xss, sqli)
        :param cves: lista o str de CVEs (ej: CVE-2023-1234)
        :param include_categories: lista o str de categorías (ej: exposures, misconfiguration)
        :param headers: dict de headers personalizados (opcional)
        :param cookies: dict o str de cookies (opcional)
        :return: lista de hallazgos (dict)
        """
        nuclei_exec, bin_name = self._find_nuclei_exec()
        if not nuclei_exec:
            self.logger.error(
                f"Nuclei no está instalado o no se encuentra en el PATH. "
                f"Descárgalo de https://github.com/projectdiscovery/nuclei/releases y colócalo en el PATH, en la raíz del proyecto como {bin_name}, en tools/nuclei/ o en windows/ o linux/. "
                f"También puedes configurar nuclei_path en config."
            )
            return []
        cmd = [nuclei_exec, "-json"]
        # Soporte para lista de URLs
        if url_list:
            if isinstance(url_list, str) and os.path.isfile(url_list):
                cmd += ["-l", url_list]
            elif isinstance(url_list, (list, tuple)):
                # Guardar lista temporalmente
                import tempfile
                with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as tmpf:
                    for u in url_list:
                        tmpf.write(u.strip() + "\n")
                    tmp_path = tmpf.name
                cmd += ["-l", tmp_path]
            else:
                self.logger.error("url_list debe ser una lista de URLs o una ruta a archivo válido.")
                return []
        elif target:
            cmd += ["-u", target]
        else:
            self.logger.error("Debes especificar un target o una lista de URLs.")
            return []
        # Integración profesional de templates personalizados
        templates_path = templates or self.templates or self.get_templates_path()
        if templates_path:
            cmd += ["-t", templates_path]
        # Añadir concurrencia/hilos
        if threads:
            cmd += ["-c", str(threads)]
        # Añadir selección de severidad
        if severity:
            if isinstance(severity, (list, tuple)):
                cmd += ["-severity", ",".join(severity)]
            else:
                cmd += ["-severity", str(severity)]
        # Añadir tags
        if tags:
            if isinstance(tags, (list, tuple)):
                cmd += ["-tags", ",".join(tags)]
            else:
                cmd += ["-tags", str(tags)]
        # Añadir CVEs
        if cves:
            if isinstance(cves, (list, tuple)):
                cmd += ["-cves", ",".join(cves)]
            else:
                cmd += ["-cves", str(cves)]
        # Añadir categorías
        if include_categories:
            if isinstance(include_categories, (list, tuple)):
                cmd += ["-include-categories", ",".join(include_categories)]
            else:
                cmd += ["-include-categories", str(include_categories)]
        # Añadir headers personalizados
        if headers:
            if isinstance(headers, dict):
                for k, v in headers.items():
                    cmd += ["-H", f"{k}: {v}"]
            elif isinstance(headers, (list, tuple)):
                for h in headers:
                    cmd += ["-H", str(h)]
            elif isinstance(headers, str):
                cmd += ["-H", headers]
        # Añadir cookies
        if cookies:
            if isinstance(cookies, dict):
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                cmd += ["-cookie", cookie_str]
            elif isinstance(cookies, str):
                cmd += ["-cookie", cookies]
        # Añadir rate limit
        if rate_limit:
            cmd += ["-rate-limit", str(rate_limit)]
        # Añadir proxy
        if proxy:
            cmd += ["-proxy", proxy]
        if extra_args:
            cmd += extra_args
        real_timeout = timeout if timeout else self.timeout
        self.logger.info(f"Ejecutando Nuclei: {' '.join(cmd)} (timeout={real_timeout}s)")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=real_timeout)
            findings = []
            if result.returncode != 0:
                self.logger.error(f"Nuclei error: {result.stderr}")
                return []
            # Parsear resultados JSON línea por línea
            for line in result.stdout.splitlines():
                try:
                    findings.append(json.loads(line))
                except Exception:
                    continue
            # Guardar salida si se solicita
            if output_file:
                try:
                    with open(output_file, "w", encoding="utf-8") as f:
                        json.dump(findings, f, indent=2, ensure_ascii=False)
                except Exception as e:
                    self.logger.error(f"No se pudo guardar el archivo de salida: {e}")
            return findings
        except subprocess.TimeoutExpired:
            self.logger.error(f"Nuclei timeout tras {real_timeout}s")
            return []
        except Exception as e:
            self.logger.error(f"Error ejecutando Nuclei: {e}")
            return []
        """
        Ejecuta Nuclei sobre uno o varios objetivos y retorna hallazgos como lista de dicts.
        :param target: URL objetivo (str) o None si se usa url_list
        :param url_list: lista de URLs o ruta a archivo de URLs (opcional)
        :param extra_args: lista de argumentos extra para Nuclei
        :param templates: ruta a plantillas personalizadas (opcional)
        :param timeout: timeout de ejecución en segundos (opcional)
        :param severity: lista o str de severidades (critical, high, medium, low, info)
        :param tags: lista o str de tags (ej: xss, sqli)
        :param cves: lista o str de CVEs (ej: CVE-2023-1234)
        :param include_categories: lista o str de categorías (ej: exposures, misconfiguration)
        :param headers: dict de headers personalizados (opcional)
        :param cookies: dict o str de cookies (opcional)
        :return: lista de hallazgos (dict)
        """
        nuclei_exec, bin_name = self._find_nuclei_exec()
        if not nuclei_exec:
            self.logger.error(
                f"Nuclei no está instalado o no se encuentra en el PATH. "
                f"Descárgalo de https://github.com/projectdiscovery/nuclei/releases y colócalo en el PATH, en la raíz del proyecto como {bin_name}, en tools/nuclei/ o en windows/ o linux/. "
                f"También puedes configurar nuclei_path en config."
            )
            return []
        cmd = [nuclei_exec, "-json"]
        # Soporte para lista de URLs
        if url_list:
            if isinstance(url_list, str) and os.path.isfile(url_list):
                cmd += ["-l", url_list]
            elif isinstance(url_list, (list, tuple)):
                # Guardar lista temporalmente
                import tempfile
                with tempfile.NamedTemporaryFile(mode="w", delete=False, encoding="utf-8") as tmpf:
                    for u in url_list:
                        tmpf.write(u.strip() + "\n")
                    tmp_path = tmpf.name
                cmd += ["-l", tmp_path]
            else:
                self.logger.error("url_list debe ser una lista de URLs o una ruta a archivo válido.")
                return []
        elif target:
            cmd += ["-u", target]
        else:
            self.logger.error("Debes especificar un target o una lista de URLs.")
            return []
        # Añadir selección de severidad
        if severity:
            if isinstance(severity, (list, tuple)):
                cmd += ["-severity", ",".join(severity)]
            else:
                cmd += ["-severity", str(severity)]
        # Añadir tags
        if tags:
            if isinstance(tags, (list, tuple)):
                cmd += ["-tags", ",".join(tags)]
            else:
                cmd += ["-tags", str(tags)]
        # Añadir CVEs
        if cves:
            if isinstance(cves, (list, tuple)):
                cmd += ["-cves", ",".join(cves)]
            else:
                cmd += ["-cves", str(cves)]
        # Añadir categorías
        if include_categories:
            if isinstance(include_categories, (list, tuple)):
                cmd += ["-include-categories", ",".join(include_categories)]
            else:
                cmd += ["-include-categories", str(include_categories)]
        # Añadir headers personalizados
        if headers:
            if isinstance(headers, dict):
                for k, v in headers.items():
                    cmd += ["-H", f"{k}: {v}"]
            elif isinstance(headers, (list, tuple)):
                for h in headers:
                    cmd += ["-H", str(h)]
            elif isinstance(headers, str):
                cmd += ["-H", headers]
        # Añadir cookies
        if cookies:
            if isinstance(cookies, dict):
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                cmd += ["-cookie", cookie_str]
            elif isinstance(cookies, str):
                cmd += ["-cookie", cookies]
        # Añadir rate limit
        if rate_limit:
            cmd += ["-rate-limit", str(rate_limit)]
        # Añadir proxy
        if proxy:
            cmd += ["-proxy", proxy]
        if extra_args:
            cmd += extra_args
        real_timeout = timeout if timeout else self.timeout
        self.logger.info(f"Ejecutando Nuclei: {' '.join(cmd)} (timeout={real_timeout}s)")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=real_timeout)
            findings = []
            for line in result.stdout.splitlines():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    self.logger.debug(f"Línea no JSON ignorada: {line}")
                    continue
            if result.stderr:
                self.logger.warning(f"Nuclei stderr: {result.stderr.strip()}")
            if output_file:
                from datetime import datetime
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                base, ext = os.path.splitext(output_file)
                output_file_ts = f"{base}_{timestamp}{ext}"
                try:
                    with open(output_file_ts, "w", encoding="utf-8") as f:
                        json.dump(findings, f, indent=2, ensure_ascii=False)
                    self.logger.info(f"Salida de Nuclei guardada en {output_file_ts}")
                except Exception as e:
                    self.logger.error(f"No se pudo guardar el output de Nuclei: {e}")
            self.logger.info(f"Nuclei hallazgos: {len(findings)}")
            return findings
        except subprocess.TimeoutExpired:
            self.logger.error(f"Timeout: Nuclei no respondió en {real_timeout} segundos.")
            return []
        except Exception as e:
            self.logger.error(f"Error ejecutando Nuclei: {e}")
            return []
