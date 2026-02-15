"""
Orquestador principal del framework websec-framework.
"""
import argparse
from core.crawler import Crawler
from core.fingerprint import Fingerprinter
from core.scanner import Scanner
from core.validator import Validator
from core.reporter import Reporter
# Importar módulos de vulnerabilidades
from modules.xss import XSSModule
from modules.sqli import SQLiModule
from modules.csrf import CSRFModule
from modules.headers import HeadersModule
from modules.cors import CORSModule
from modules.auth import AuthModule
from modules.lfi import LFIModule



from core.external.nuclei_runner import NucleiRunner


def print_help():
    help_text = """
WebSec Framework - Escaneo profesional de seguridad web

Uso:
    python run.py <target> [opciones]
    python run.py --nuclei-url-list <archivo_urls> [opciones]

Argumentos:
    target                URL objetivo a analizar (ej: https://example.com)

Opciones generales:
    --config <ruta>       Ruta a archivo de configuración YAML (por defecto: config/target.yaml)
    --help                Muestra esta ayuda extendida

Integración de herramientas externas:
    --nuclei              Orquesta Nuclei (plantillas CVE, resultados JSON)
    --nuclei-url-list <archivo>  Escanea una lista de URLs (una por línea)
    --nuclei-severity     Filtrar por severidad (critical,high,medium,low,info)
    --nuclei-tags         Filtrar por tags (ej: xss,sqli)
    --nuclei-cves         Filtrar por CVEs (ej: CVE-2023-1234,CVE-2022-5678)
    --nuclei-categories   Filtrar por categorías (ej: exposures,misconfiguration)
    --nuclei-header <header>     Añadir header personalizado (puede usarse varias veces)
    --nuclei-cookie <cookie>     Añadir cookies (formato: "key1=val1; key2=val2")
    --nuclei-rate-limit <n>      Limitar requests por segundo (ej: 10)
    --nuclei-proxy <url>         Usar proxy HTTP/SOCKS (ej: http://127.0.0.1:8080)
    --nuclei-threads <n>         Número de hilos/concurrencia para escaneo masivo (ej: 4, 10, 50)

    Ejecución concurrente:
        - El framework ejecuta crawling, fingerprinting y escaneo de vulnerabilidades en paralelo para máxima eficiencia.
        - El escaneo con Nuclei sobre múltiples URLs se realiza en paralelo usando --nuclei-threads para controlar el número de hilos.
        - Ejemplo: python run.py --nuclei-url-list urls.txt --nuclei --nuclei-threads 10

    Notas profesionales:
        - El binario portable de wkhtmltopdf debe estar en tools/wkhtmltopdf/ para exportar a PDF sin instalación.
        - El framework detecta y solicita elevación de privilegios automáticamente si es necesario en Windows.
        - Todos los formatos de salida soportan exportación masiva y agrupación avanzada.
    --nuclei-templates <ruta>    Ruta a templates personalizados de Nuclei
    --nuclei-update-templates    Actualiza los templates de Nuclei automáticamente
    --nuclei-output <archivo>    Guardar salida de Nuclei en archivo (JSON, YAML, HTML, PDF, CSV)
    --nuclei-output-format <fmt> Formato de salida: json, yaml, html, pdf, csv (por defecto: json)

Ejemplos de exportación:
    python run.py <target> --nuclei --nuclei-output report.json --nuclei-output-format json
    python run.py <target> --nuclei --nuclei-output report.yaml --nuclei-output-format yaml
    python run.py <target> --nuclei --nuclei-output report.html --nuclei-output-format html
    python run.py <target> --nuclei --nuclei-output report.pdf --nuclei-output-format pdf
    python run.py <target> --nuclei --nuclei-output report.csv --nuclei-output-format csv

Para PDF necesitas instalar weasyprint: pip install weasyprint
    (Próximamente: sqlmap, ZAP)

Flujo de ejecución:
    1. Descubrimiento y crawling inteligente
    2. Fingerprinting tecnológico
    3. Escaneo automatizado de vulnerabilidades (XSS, SQLi, CSRF, headers, CORS, auth, LFI)
    4. Validación de falsos positivos
    5. Generación de reportes profesionales (HTML/JSON)

Ejemplo de uso avanzado:
    python run.py https://example.com --nuclei --nuclei-severity high,critical --nuclei-tags xss,sqli --nuclei-cves CVE-2023-1234 --nuclei-categories exposures --nuclei-header "Authorization: Bearer TOKEN" --nuclei-cookie "sessionid=abc; csrftoken=xyz"
    python run.py --nuclei-url-list urls.txt --nuclei --nuclei-severity high
"""
    print(help_text)
def main():
    import sys
    if '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        return

    parser = argparse.ArgumentParser(description="WebSec Framework - Escaneo profesional de seguridad web", add_help=False)
    parser.add_argument("target", nargs='?', help="URL objetivo a analizar")
    parser.add_argument("--config", help="Ruta a archivo de configuración", default="config/target.yaml")
    parser.add_argument("--nuclei", action="store_true", help="Ejecutar Nuclei sobre el objetivo")
    parser.add_argument("--nuclei-output-format", choices=["json", "yaml", "html", "pdf", "csv"], default="json", help="Formato de salida de Nuclei: json, yaml, html, pdf, csv")
    # Opciones avanzadas para Nuclei
    parser.add_argument("--nuclei-severity", help="Filtrar por severidad (critical,high,medium,low,info)")
    parser.add_argument("--nuclei-tags", help="Filtrar por tags (ej: xss,sqli)")
    parser.add_argument("--nuclei-cves", help="Filtrar por CVEs (ej: CVE-2023-1234,CVE-2022-5678)")
    parser.add_argument("--nuclei-categories", help="Filtrar por categorías (ej: exposures,misconfiguration)")
    parser.add_argument("--nuclei-url-list", help="Ruta a archivo de URLs para escaneo masivo con Nuclei")
    parser.add_argument("--nuclei-header", action="append", help="Añadir header personalizado (puede usarse varias veces)")
    parser.add_argument("--nuclei-cookie", help="Añadir cookies (formato: 'key1=val1; key2=val2')")
    parser.add_argument("--nuclei-rate-limit", type=int, help="Limitar requests por segundo (ej: 10)")
    parser.add_argument("--nuclei-proxy", help="Usar proxy HTTP/SOCKS (ej: http://127.0.0.1:8080)")
    parser.add_argument("--nuclei-threads", type=int, help="Número de hilos/concurrencia (ej: 50)")
    parser.add_argument("--nuclei-templates", help="Ruta a templates personalizados de Nuclei")
    parser.add_argument("--nuclei-update-templates", action="store_true", help="Actualiza los templates de Nuclei automáticamente")
    parser.add_argument("--nuclei-output", help="Guardar salida JSON de Nuclei en archivo")

    args = parser.parse_args()

    # Si se solicita actualización de templates, ejecutarla y salir
    if getattr(args, "nuclei_update_templates", False):
        nuclei = NucleiRunner({})
        ok = nuclei.update_templates()
        if ok:
            print("Templates de Nuclei actualizados correctamente.")
        else:
            print("Error actualizando templates de Nuclei. Revisa el log.")
        return

    if not args.target and not args.nuclei_url_list:
        print_help()
        return

    # Cargar configuración (placeholder)
    config = {}

    # Solo ejecutar crawling, fingerprinting y escaneo si hay un target específico
    if args.target:
        # Crear timestamp compartido para todos los módulos
        from datetime import datetime
        scan_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = f"reports/scan_{scan_timestamp}"
        
        # Compartir timestamp y directorio en config
        config['scan_timestamp'] = scan_timestamp
        config['report_dir'] = report_dir
        
        # Ejecución concurrente de crawling, fingerprinting y escaneo
        import concurrent.futures
        
        crawler = None
        fingerprinter = None
        scanner = None
        
        def run_crawler():
            nonlocal crawler
            crawler = Crawler(args.target, config)
            crawler.scan_timestamp = scan_timestamp
            crawler.report_dir = report_dir
            crawler.run()
            return crawler
            
        def run_finger():
            nonlocal fingerprinter
            fingerprinter = Fingerprinter(args.target, config)
            fingerprinter.scan_timestamp = scan_timestamp
            fingerprinter.report_dir = report_dir
            fingerprinter.run()
            return fingerprinter
            
        def run_scanner():
            nonlocal scanner
            scanner = Scanner(args.target, config)
            scanner.register_module(XSSModule(config))
            scanner.register_module(SQLiModule(config))
            scanner.register_module(CSRFModule(config))
            scanner.register_module(HeadersModule(config))
            scanner.register_module(CORSModule(config))
            scanner.register_module(AuthModule(config))
            scanner.register_module(LFIModule(config))
            scanner.run()
            return scanner
            
        # Control de threads: máximo 3 tareas concurrentes (crawling, fingerprint, escaneo)
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(run_crawler),
                executor.submit(run_finger),
                executor.submit(run_scanner)
            ]
            concurrent.futures.wait(futures)

        # Fase 4: Validación de falsos positivos (placeholder)
        validator = Validator(config)
        # for finding in scanner.findings:
        #     validator.validate(finding)

        # Fase 5: Reporte
        reporter = Reporter(config)
        # reporter.generate(scanner.findings, output_dir=report_dir, target_url=args.target, scan_timestamp=scan_timestamp)
        
        print(f"\n[+] Escaneo completado. Reportes guardados en: {report_dir}")
        print(f"    - Crawling: crawl_urls.json, crawl_forms.json, crawl_js_endpoints.json, crawl_tree.json")
        print(f"    - Fingerprinting: fingerprint.json")
        print(f"    - Vulnerabilidades: vulnerability_report.html, vulnerability_report.json")

    # Ejemplo de integración avanzada con Nuclei
    if args.nuclei:
        nuclei = NucleiRunner(config)
        # Parsear argumentos avanzados
        severity = [s.strip() for s in args.nuclei_severity.split(",")] if args.nuclei_severity else None
        tags = [t.strip() for t in args.nuclei_tags.split(",")] if args.nuclei_tags else None
        cves = [c.strip() for c in args.nuclei_cves.split(",")] if args.nuclei_cves else None
        categories = [cat.strip() for cat in args.nuclei_categories.split(",")] if args.nuclei_categories else None
        url_list = args.nuclei_url_list if args.nuclei_url_list else None
        headers = args.nuclei_header if args.nuclei_header else None
        cookies = args.nuclei_cookie if args.nuclei_cookie else None
        # Si hay lista de URLs, ejecutar Nuclei concurrentemente por URL (control de threads)
        nuclei_findings = []
        if url_list and isinstance(url_list, str):
            with open(url_list, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
        elif url_list and isinstance(url_list, (list, tuple)):
            urls = url_list
        else:
            urls = [args.target]
        max_threads = args.nuclei_threads if args.nuclei_threads else 4
        
        def scan_url(url):
            return nuclei.run(
                target=url,
                severity=severity,
                tags=tags,
                cves=cves,
                categories=categories,
                headers=headers,
                cookies=cookies,
                rate_limit=args.nuclei_rate_limit,
                proxy=args.nuclei_proxy,
                templates_path=args.nuclei_templates
            )
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(scan_url, url) for url in urls]
            for future in concurrent.futures.as_completed(futures):
                try:
                    findings = future.result()
                    if findings:
                        nuclei_findings.extend(findings)
                except Exception as e:
                    print(f"[!] Error en escaneo de URL: {e}")
        
        # Guardar resultados si se especificó output
        if args.nuclei_output:
            import os
            import json
            import tempfile
            from jinja2 import Template
            
            fmt = args.nuclei_output_format
            try:
                if fmt == 'json':
                    with open(args.nuclei_output, 'w', encoding='utf-8') as f:
                        json.dump(nuclei_findings, f, indent=2, ensure_ascii=False)
                elif fmt == 'yaml':
                    import yaml
                    with open(args.nuclei_output, 'w', encoding='utf-8') as f:
                        yaml.dump(nuclei_findings, f, allow_unicode=True, default_flow_style=False)
                elif fmt == 'csv':
                    import csv
                    with open(args.nuclei_output, 'w', newline='', encoding='utf-8') as f:
                        if nuclei_findings:
                            fieldnames = ['name', 'severity', 'template', 'tags', 'matched-at']
                            writer = csv.DictWriter(f, fieldnames=fieldnames)
                            writer.writeheader()
                            for finding in nuclei_findings:
                                info = finding.get('info', {})
                                writer.writerow({
                                    'name': info.get('name', '-'),
                                    'severity': info.get('severity', '-'),
                                    'template': finding.get('template', '-'),
                                    'tags': ','.join(info.get('tags', [])),
                                    'matched-at': finding.get('matched-at', '-')
                                })
                elif fmt == 'html':
                    template_path = os.path.join(os.path.dirname(__file__), 'templates', 'nuclei_report.html')
                    with open(template_path, 'r', encoding='utf-8') as tplf:
                        html_template = tplf.read()
                    from collections import defaultdict
                    grouped = defaultdict(list)
                    for f in nuclei_findings:
                        sev = f.get('info', {}).get('severity', 'unknown').lower()
                        grouped[sev].append(f)
                    t = Template(html_template)
                    html = t.render(grouped=grouped)
                    with open(args.nuclei_output, 'w', encoding='utf-8') as f:
                        f.write(html)
                elif fmt == 'pdf':
                    import sys
                    template_path = os.path.join(os.path.dirname(__file__), 'templates', 'nuclei_report.html')
                    with open(template_path, 'r', encoding='utf-8') as tplf:
                        html_template = tplf.read()
                    from collections import defaultdict
                    grouped = defaultdict(list)
                    for f in nuclei_findings:
                        sev = f.get('info', {}).get('severity', 'unknown').lower()
                        grouped[sev].append(f)
                    t = Template(html_template)
                    html = t.render(grouped=grouped)
                    # Guardar HTML temporalmente
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.html', mode='w', encoding='utf-8') as tmpf:
                        tmpf.write(html)
                        html_path = tmpf.name
                    # Buscar wkhtmltopdf portable en tools/wkhtmltopdf/
                    import platform
                    is_windows = platform.system().lower().startswith('win')
                    wkhtml_bin = os.path.join(os.path.dirname(__file__), 'tools', 'wkhtmltopdf', 'wkhtmltopdf.exe' if is_windows else 'wkhtmltopdf')
                    if not os.path.isfile(wkhtml_bin):
                        print(f"[!] wkhtmltopdf no encontrado en {wkhtml_bin}. Descárgalo de https://wkhtmltopdf.org/downloads.html y colócalo en tools/wkhtmltopdf/")
                        return
                    import subprocess
                    def is_admin():
                        if not is_windows:
                            return True
                        try:
                            import ctypes
                            return ctypes.windll.shell32.IsUserAnAdmin() != 0
                        except Exception:
                            return False
                    if is_windows and not is_admin():
                        print("[!] Se requieren privilegios de administrador para exportar a PDF con wkhtmltopdf en Windows. Relanzando con elevación...")
                        import shlex
                        params = ' '.join([shlex.quote(arg) for arg in sys.argv])
                        ctypes = __import__('ctypes')
                        shell32 = ctypes.windll.shell32
                        # 1 = SW_SHOWNORMAL
                        ret = shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                        if int(ret) <= 32:
                            print("[!] No se pudo elevar privilegios. Ejecuta este comando como administrador.")
                        sys.exit(0)
                    try:
                        subprocess.run([wkhtml_bin, html_path, args.nuclei_output], check=True)
                        print(f"[+] PDF generado correctamente usando wkhtmltopdf en {args.nuclei_output}")
                    except Exception as e:
                        print(f"[!] Error ejecutando wkhtmltopdf: {e}")
                    finally:
                        try:
                            os.remove(html_path)
                        except Exception:
                            pass
                print(f"[+] Resultados de Nuclei guardados en {args.nuclei_output} ({fmt})")
            except Exception as e:
                print(f"[!] Error guardando el output de Nuclei: {e}")
        # Correlación avanzada: agrupación por severidad y tipo
        from collections import defaultdict, Counter
        grouped = defaultdict(list)
        by_type = defaultdict(list)
        for f in nuclei_findings:
            sev = f.get('info', {}).get('severity', 'unknown').lower()
            grouped[sev].append(f)
            for tag in f.get('info', {}).get('tags', []):
                by_type[tag].append(f)
        print("\n=== Resumen de Hallazgos de Nuclei ===")
        for sev in sorted(grouped.keys()):
            print(f"[+] {sev.upper()}: {len(grouped[sev])} hallazgos")
        print("\n=== Detalle agrupado por tipo (tag) ===")
        for tag in sorted(by_type.keys()):
            print(f"[+] {tag}: {len(by_type[tag])} hallazgos")
        print("\n=== Hallazgos Detallados ===")
        for sev in sorted(grouped.keys()):
            print(f"\n--- {sev.upper()} ---")
            for f in grouped[sev]:
                name = f.get('info', {}).get('name', '-')
                template = f.get('template', '-')
                tags = ','.join(f.get('info', {}).get('tags', []))
                print(f"  - {name} | Template: {template} | Tags: {tags}")

if __name__ == "__main__":
    main()
    # Despliegue automático del servidor Flask para visualización
    print("\n[INFO] Puedes visualizar el árbol de crawling ejecutando:")
    print("    python app.py")
    print("Luego abre http://localhost:5000/crawl_tree en tu navegador.")
