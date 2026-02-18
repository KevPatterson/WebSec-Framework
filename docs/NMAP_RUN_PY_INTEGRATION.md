# Integración de Nmap en run.py

Este documento describe los cambios necesarios para integrar el módulo de Nmap en el archivo `run.py`.

## Cambios Necesarios

### 1. Importar el Módulo (Línea ~27)

Agregar después de las otras importaciones de módulos:

```python
from modules.port_scan import PortScanModule
```

### 2. Agregar Argumentos en print_help() (Línea ~360)

Agregar después de la sección de ZAP:

```python
================================================================================
NMAP - ESCANEO DE PUERTOS Y SERVICIOS (NUEVO v0.8.0)
================================================================================

    --nmap                Ejecuta Nmap para escaneo de puertos
    --nmap-scan-type <type>
                          Tipo de escaneo: quick, full, service, vuln
                          (por defecto: quick)
    --nmap-ports <ports>  Puertos a escanear (ej: "80,443,8080" o "1-1000")
                          (por defecto: puertos comunes en quick scan)
    --nmap-detect-os      Activar detección de sistema operativo
                          (requiere privilegios de administrador)
    --nmap-timeout <n>    Timeout en segundos (por defecto: 300)
    --nmap-output <archivo>
                          Guardar salida de Nmap en archivo JSON
```

### 3. Agregar Ejemplo en print_help() (Línea ~435)

Agregar después de los ejemplos de ZAP:

```python
Escaneo con Nmap (puertos comunes):
    python run.py https://example.com --nmap

Escaneo completo con Nmap:
    python run.py https://example.com --nmap --nmap-scan-type full

Escaneo de servicios con Nmap:
    python run.py https://example.com --nmap --nmap-scan-type service --nmap-ports "1-1000"

Escaneo combinado (Nmap + Nuclei + SQLMap + ZAP):
    python run.py https://example.com --nmap --nuclei --sqlmap --zap
```

### 4. Agregar Parseo de Argumentos en main() (Línea ~650)

Agregar después de los argumentos de ZAP:

```python
# Argumentos de Nmap
parser.add_argument('--nmap', action='store_true', help='Ejecutar Nmap para escaneo de puertos')
parser.add_argument('--nmap-scan-type', type=str, default='quick', 
                    help='Tipo de escaneo: quick, full, service, vuln (default: quick)')
parser.add_argument('--nmap-ports', type=str, default=None,
                    help='Puertos a escanear (ej: "80,443,8080" o "1-1000")')
parser.add_argument('--nmap-detect-os', action='store_true',
                    help='Activar detección de OS (requiere privilegios)')
parser.add_argument('--nmap-timeout', type=int, default=300,
                    help='Timeout en segundos (default: 300)')
parser.add_argument('--nmap-output', type=str, default=None,
                    help='Guardar salida de Nmap en archivo JSON')
```

### 5. Registrar Módulo en Scanner (Línea ~710)

Agregar después del registro de otros módulos:

```python
# Registrar módulo de Port Scan (Nmap) si está habilitado
if args.nmap:
    config["nmap_scan_type"] = args.nmap_scan_type
    config["nmap_ports"] = args.nmap_ports
    config["nmap_detect_os"] = args.nmap_detect_os
    config["nmap_timeout"] = args.nmap_timeout
    scanner.register_module(PortScanModule(config))
```

### 6. Exportar Resultados de Nmap (Línea ~950)

Agregar después de la sección de ZAP:

```python
# Integración con Nmap
if args.nmap:
    print("\n=== Ejecutando Nmap ===")
    from core.external.nmap_runner import NmapRunner
    
    nmap_config = {
        "nmap_timeout": args.nmap_timeout,
        "nmap_scan_type": args.nmap_scan_type
    }
    nmap = NmapRunner(nmap_config)
    
    if not nmap.is_available():
        print("[!] Nmap no está disponible. Instala nmap y python-nmap:")
        print("    - Nmap: https://nmap.org/download.html")
        print("    - python-nmap: pip install python-nmap")
    else:
        # Extraer host del target
        from urllib.parse import urlparse
        parsed = urlparse(args.target)
        target_host = parsed.hostname or parsed.netloc or args.target
        
        print(f"[*] Target: {target_host}")
        print(f"[*] Scan Type: {args.nmap_scan_type}")
        if args.nmap_ports:
            print(f"[*] Ports: {args.nmap_ports}")
        if args.nmap_detect_os:
            print(f"[*] OS Detection: Enabled (requires privileges)")
        
        try:
            # Ejecutar escaneo según el tipo
            if args.nmap_scan_type == "quick":
                nmap_results = nmap.quick_scan(target_host)
            elif args.nmap_scan_type == "full":
                nmap_results = nmap.full_scan(target_host, detect_os=args.nmap_detect_os)
            elif args.nmap_scan_type == "service":
                ports = args.nmap_ports or "1-1000"
                nmap_results = nmap.service_scan(target_host, ports=ports)
            elif args.nmap_scan_type == "vuln":
                ports = args.nmap_ports or "1-1000"
                nmap_results = nmap.vulnerability_scan(target_host, ports=ports)
            else:
                print(f"[!] Tipo de escaneo desconocido: {args.nmap_scan_type}")
                nmap_results = None
            
            if nmap_results:
                # Obtener resumen de puertos abiertos
                summary = nmap.get_open_ports_summary(nmap_results)
                
                print(f"\n[+] Escaneo completado: {len(summary)} puerto(s) abierto(s)")
                
                # Mostrar resumen
                for port_info in summary[:10]:  # Mostrar primeros 10
                    service_str = f"{port_info['service']}"
                    if port_info['product']:
                        service_str += f" ({port_info['product']}"
                        if port_info['version']:
                            service_str += f" {port_info['version']}"
                        service_str += ")"
                    
                    print(f"  - {port_info['port']}/{port_info['protocol']}: {service_str}")
                
                if len(summary) > 10:
                    print(f"  ... y {len(summary) - 10} puerto(s) más")
                
                # Guardar resultados si se especificó
                if args.nmap_output:
                    nmap.export_results(nmap_results, args.nmap_output)
                    print(f"[+] Resultados de Nmap guardados en {args.nmap_output}")
            else:
                print("[!] No se obtuvieron resultados del escaneo")
        
        except Exception as e:
            print(f"[!] Error ejecutando Nmap: {e}")
```

## Código Completo para Copiar

### Importación (agregar en línea ~27)
```python
from modules.port_scan import PortScanModule
```

### Argumentos del Parser (agregar en línea ~650)
```python
# Argumentos de Nmap
parser.add_argument('--nmap', action='store_true', help='Ejecutar Nmap para escaneo de puertos')
parser.add_argument('--nmap-scan-type', type=str, default='quick', 
                    help='Tipo de escaneo: quick, full, service, vuln (default: quick)')
parser.add_argument('--nmap-ports', type=str, default=None,
                    help='Puertos a escanear (ej: "80,443,8080" o "1-1000")')
parser.add_argument('--nmap-detect-os', action='store_true',
                    help='Activar detección de OS (requiere privilegios)')
parser.add_argument('--nmap-timeout', type=int, default=300,
                    help='Timeout en segundos (default: 300)')
parser.add_argument('--nmap-output', type=str, default=None,
                    help='Guardar salida de Nmap en archivo JSON')
```

### Registro del Módulo (agregar en línea ~710)
```python
# Registrar módulo de Port Scan (Nmap) si está habilitado
if args.nmap:
    config["nmap_scan_type"] = args.nmap_scan_type
    config["nmap_ports"] = args.nmap_ports
    config["nmap_detect_os"] = args.nmap_detect_os
    config["nmap_timeout"] = args.nmap_timeout
    scanner.register_module(PortScanModule(config))
```

## Verificación

Después de realizar los cambios, verifica que todo funcione:

```bash
# Ver ayuda actualizada
python run.py --help

# Probar escaneo rápido
python run.py https://scanme.nmap.org --nmap

# Probar con opciones
python run.py https://scanme.nmap.org --nmap --nmap-scan-type service --nmap-ports "22,80,443"
```

## Notas Importantes

1. **Orden de Importación**: Asegúrate de importar `PortScanModule` después de los otros módulos
2. **Privilegios**: Algunos escaneos (como `--nmap-detect-os`) requieren privilegios de administrador
3. **Timeout**: El timeout por defecto es 300 segundos (5 minutos), ajústalo según necesidad
4. **Integración**: El módulo se integra automáticamente con el Scanner y genera reportes consolidados

## Troubleshooting

### Error: "Nmap no está disponible"
```bash
# Instalar Nmap
# Windows: https://nmap.org/download.html
# Linux: sudo apt-get install nmap
# macOS: brew install nmap

# Instalar python-nmap
pip install python-nmap
```

### Error: "Permission denied"
```bash
# Ejecutar con privilegios (solo para --nmap-detect-os)
sudo python run.py https://example.com --nmap --nmap-detect-os
```

### Escaneo muy lento
```bash
# Usar quick scan en lugar de full
python run.py https://example.com --nmap --nmap-scan-type quick

# O limitar puertos
python run.py https://example.com --nmap --nmap-ports "80,443"
```
