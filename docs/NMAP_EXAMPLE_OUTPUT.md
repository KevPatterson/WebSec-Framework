# Ejemplo de Salida de Nmap Integration

Este documento muestra ejemplos reales de la salida generada por la integración de Nmap.

## 📊 Ejemplo 1: Escaneo Rápido (Quick Scan)

### Comando
```bash
python run.py https://scanme.nmap.org --nmap
```

### Salida en Consola
```
================================================================================
                    WebSec Framework - Escaneo Profesional
================================================================================

[*] Target: https://scanme.nmap.org
[*] Scan Type: quick
[*] Timestamp: 20260218_143022

[PortScan] Iniciando escaneo de puertos en: scanme.nmap.org
[PortScan] Tipo de escaneo: quick
[PortScan] Escaneando scanme.nmap.org en puertos 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443 con argumentos: -sV -T4

[PortScan] Puerto abierto: 45.33.32.156:22/tcp - ssh (OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13)
[PortScan] Puerto abierto: 45.33.32.156:80/tcp - http (Apache httpd 2.4.7)
[PortScan] Puerto abierto: 45.33.32.156:443/tcp - https (Apache httpd 2.4.7)

[PortScan] Escaneo completado: 3 hallazgos
[PortScan] Hallazgos exportados en: reports/scan_20260218_143022/port_scan_findings.json

[+] Escaneo completado: 3 puerto(s) abierto(s)

  - 22/tcp: ssh (OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13)
  - 80/tcp: http (Apache httpd 2.4.7)
  - 443/tcp: https (Apache httpd 2.4.7)

================================================================================
ESTADÍSTICAS DE VALIDACIÓN
================================================================================
Total de hallazgos: 3
Validados (confianza >= 60): 3
Baja confianza (< 60): 0
Confianza promedio: 85%

Distribución por confianza:
  90-100% (Muy alta): 0
  70-89%  (Alta):     3
  60-69%  (Media):    0
  0-59%   (Baja):     0
================================================================================

[+] Reporte consolidado JSON exportado en: reports/scan_20260218_143022/vulnerability_scan_consolidated.json
[+] Reporte HTML profesional generado en: reports/scan_20260218_143022/vulnerability_report.html
```

### Archivo: port_scan_findings.json
```json
{
  "scan_info": {
    "target": "https://scanme.nmap.org",
    "timestamp": "20260218_143022",
    "module": "port_scan",
    "scan_type": "quick",
    "total_findings": 3
  },
  "scan_results": {
    "target": "scanme.nmap.org",
    "scan_info": {
      "tcp": {
        "method": "syn",
        "services": "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"
      }
    },
    "hosts": {
      "45.33.32.156": {
        "hostname": "scanme.nmap.org",
        "state": "up",
        "protocols": {
          "tcp": {
            "22": {
              "state": "open",
              "name": "ssh",
              "product": "OpenSSH",
              "version": "6.6.1p1 Ubuntu 2ubuntu2.13",
              "extrainfo": "Ubuntu Linux; protocol 2.0",
              "cpe": "cpe:/o:linux:linux_kernel"
            },
            "80": {
              "state": "open",
              "name": "http",
              "product": "Apache httpd",
              "version": "2.4.7",
              "extrainfo": "(Ubuntu)",
              "cpe": "cpe:/a:apache:http_server:2.4.7"
            },
            "443": {
              "state": "open",
              "name": "https",
              "product": "Apache httpd",
              "version": "2.4.7",
              "extrainfo": "",
              "cpe": "cpe:/a:apache:http_server:2.4.7"
            }
          }
        },
        "os": {}
      }
    }
  },
  "findings": [
    {
      "type": "open_port",
      "severity": "medium",
      "port": 22,
      "protocol": "tcp",
      "service": "ssh",
      "title": "Puerto Abierto: 22/tcp - ssh (OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13)",
      "description": "Se detectó el puerto 22/tcp abierto ejecutando ssh (OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13)",
      "recommendation": "Asegurar SSH: deshabilitar root login, usar autenticación por clave, cambiar puerto por defecto",
      "cvss": 5.3,
      "evidence": {
        "host": "45.33.32.156",
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "product": "OpenSSH",
        "version": "6.6.1p1 Ubuntu 2ubuntu2.13",
        "extrainfo": "Ubuntu Linux; protocol 2.0",
        "cpe": "cpe:/o:linux:linux_kernel"
      }
    },
    {
      "type": "open_port",
      "severity": "info",
      "port": 80,
      "protocol": "tcp",
      "service": "http",
      "title": "Puerto Abierto: 80/tcp - http (Apache httpd 2.4.7)",
      "description": "Se detectó el puerto 80/tcp abierto ejecutando http (Apache httpd 2.4.7)",
      "recommendation": "Asegurar HTTP: usar HTTPS (443), implementar security headers, mantener servidor actualizado",
      "cvss": 0.0,
      "evidence": {
        "host": "45.33.32.156",
        "port": 80,
        "protocol": "tcp",
        "service": "http",
        "product": "Apache httpd",
        "version": "2.4.7",
        "extrainfo": "(Ubuntu)",
        "cpe": "cpe:/a:apache:http_server:2.4.7"
      }
    },
    {
      "type": "open_port",
      "severity": "info",
      "port": 443,
      "protocol": "tcp",
      "service": "https",
      "title": "Puerto Abierto: 443/tcp - https (Apache httpd 2.4.7)",
      "description": "Se detectó el puerto 443/tcp abierto ejecutando https (Apache httpd 2.4.7)",
      "recommendation": "Verificar configuración SSL/TLS: usar TLS 1.2+, certificados válidos, cipher suites seguros",
      "cvss": 0.0,
      "evidence": {
        "host": "45.33.32.156",
        "port": 443,
        "protocol": "tcp",
        "service": "https",
        "product": "Apache httpd",
        "version": "2.4.7",
        "extrainfo": "",
        "cpe": "cpe:/a:apache:http_server:2.4.7"
      }
    }
  ],
  "summary": {
    "high": 0,
    "medium": 1,
    "low": 0,
    "info": 2
  }
}
```

## 📊 Ejemplo 2: Escaneo de Servicios

### Comando
```bash
python run.py https://example.com --nmap --nmap-scan-type service --nmap-ports "80,443,3306,8080"
```

### Salida en Consola
```
[PortScan] Iniciando escaneo de puertos en: example.com
[PortScan] Tipo de escaneo: service
[PortScan] Escaneando example.com en puertos 80,443,3306,8080 con argumentos: -sV -sC

[PortScan] Puerto abierto: 93.184.216.34:80/tcp - http (nginx 1.18.0)
[PortScan] Puerto abierto: 93.184.216.34:443/tcp - https (nginx 1.18.0)
[PortScan] Puerto abierto: 93.184.216.34:3306/tcp - mysql (MySQL 5.7.32)

[PortScan] Escaneo completado: 3 hallazgos
```

### Hallazgos Generados
```json
{
  "findings": [
    {
      "type": "open_port",
      "severity": "info",
      "port": 80,
      "service": "http",
      "title": "Puerto Abierto: 80/tcp - http (nginx 1.18.0)",
      "cvss": 0.0
    },
    {
      "type": "open_port",
      "severity": "info",
      "port": 443,
      "service": "https",
      "title": "Puerto Abierto: 443/tcp - https (nginx 1.18.0)",
      "cvss": 0.0
    },
    {
      "type": "open_port",
      "severity": "medium",
      "port": 3306,
      "service": "mysql",
      "title": "Puerto Abierto: 3306/tcp - mysql (MySQL 5.7.32)",
      "recommendation": "Asegurar MySQL: cambiar puerto por defecto, usar contraseñas fuertes, limitar acceso remoto",
      "cvss": 5.3
    }
  ]
}
```

## 📊 Ejemplo 3: Escaneo con Detección de OS

### Comando
```bash
sudo python run.py https://example.com --nmap --nmap-detect-os
```

### Salida en Consola
```
[PortScan] Iniciando escaneo de puertos en: example.com
[PortScan] Tipo de escaneo: quick
[PortScan] Escaneando example.com en puertos 21,22,23,25,53,80,110,143,443,445,3306,3389,5432,8080,8443 con argumentos: -sV -T4 -A

[PortScan] Puerto abierto: 93.184.216.34:80/tcp - http (nginx 1.18.0)
[PortScan] Puerto abierto: 93.184.216.34:443/tcp - https (nginx 1.18.0)
[PortScan] OS detectado: Linux 3.2 - 4.9 (95%)

[PortScan] Escaneo completado: 3 hallazgos
```

### Hallazgo de OS
```json
{
  "type": "os_detection",
  "severity": "info",
  "title": "Sistema Operativo Detectado: Linux 3.2 - 4.9",
  "description": "Nmap detectó el sistema operativo con 95% de precisión",
  "cvss": 0.0,
  "evidence": {
    "host": "93.184.216.34",
    "os_name": "Linux 3.2 - 4.9",
    "accuracy": "95",
    "all_matches": [
      {
        "name": "Linux 3.2 - 4.9",
        "accuracy": "95",
        "line": "12345",
        "osclass": [
          {
            "type": "general purpose",
            "vendor": "Linux",
            "osfamily": "Linux",
            "osgen": "3.X",
            "accuracy": "95"
          }
        ]
      }
    ]
  }
}
```

## 📊 Ejemplo 4: Escaneo de Vulnerabilidades

### Comando
```bash
python run.py https://example.com --nmap --nmap-scan-type vuln --nmap-ports "80,443"
```

### Salida en Consola
```
[PortScan] Iniciando escaneo de puertos en: example.com
[PortScan] Tipo de escaneo: vuln
[PortScan] Escaneando example.com en puertos 80,443 con argumentos: -sV --script vuln

[PortScan] Puerto abierto: 93.184.216.34:80/tcp - http (nginx 1.18.0)
[PortScan] Puerto abierto: 93.184.216.34:443/tcp - https (nginx 1.18.0)

[PortScan] Escaneo completado: 2 hallazgos
```

## 📊 Ejemplo 5: Reporte HTML Integrado

El reporte HTML incluye una sección dedicada a Port Scan:

```html
<!-- Sección de Port Scan en vulnerability_report.html -->

<div class="finding-card">
  <div class="finding-header medium">
    <span class="severity-badge medium">MEDIUM</span>
    <h3>Puerto Abierto: 22/tcp - ssh (OpenSSH 6.6.1p1)</h3>
  </div>
  
  <div class="finding-body">
    <div class="finding-section">
      <h4>Descripción</h4>
      <p>Se detectó el puerto 22/tcp abierto ejecutando ssh (OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13)</p>
    </div>
    
    <div class="finding-section">
      <h4>Evidencia</h4>
      <ul>
        <li><strong>Host:</strong> 45.33.32.156</li>
        <li><strong>Puerto:</strong> 22/tcp</li>
        <li><strong>Servicio:</strong> ssh</li>
        <li><strong>Producto:</strong> OpenSSH</li>
        <li><strong>Versión:</strong> 6.6.1p1 Ubuntu 2ubuntu2.13</li>
        <li><strong>CPE:</strong> cpe:/o:linux:linux_kernel</li>
      </ul>
    </div>
    
    <div class="finding-section">
      <h4>Recomendación</h4>
      <p>Asegurar SSH: deshabilitar root login, usar autenticación por clave, cambiar puerto por defecto</p>
    </div>
    
    <div class="finding-section">
      <h4>CVSS Score</h4>
      <span class="cvss-badge medium">5.3</span>
    </div>
  </div>
</div>
```

## 📊 Ejemplo 6: Escaneo Combinado

### Comando
```bash
python run.py https://example.com --nmap --nuclei --sqlmap --zap
```

### Salida en Consola
```
================================================================================
                    WebSec Framework - Escaneo Profesional
================================================================================

[*] Target: https://example.com
[*] Ejecutando escaneo completo con todas las herramientas

=== Ejecutando Nmap ===
[PortScan] Iniciando escaneo de puertos...
[PortScan] Escaneo completado: 3 hallazgos

=== Ejecutando Nuclei ===
[Nuclei] Ejecutando templates...
[Nuclei] Hallazgos: 5

=== Ejecutando SQLMap ===
[SQLMap] Escaneando SQL Injection...
[SQLMap] Hallazgos: 2

=== Ejecutando ZAP ===
[ZAP] Escaneando vulnerabilidades web...
[ZAP] Hallazgos: 8

================================================================================
RESUMEN FINAL
================================================================================
Total de hallazgos: 18
  - Nmap: 3
  - Nuclei: 5
  - SQLMap: 2
  - ZAP: 8

Severidad:
  - Critical: 2
  - High: 4
  - Medium: 7
  - Low: 3
  - Info: 2

[+] Reporte consolidado: reports/scan_20260218_143022/vulnerability_scan_consolidated.json
[+] Reporte HTML: reports/scan_20260218_143022/vulnerability_report.html
================================================================================
```

## 📊 Ejemplo 7: Uso Programático

```python
from core.external.nmap_runner import NmapRunner

# Inicializar
config = {"nmap_timeout": 300}
nmap = NmapRunner(config)

# Verificar disponibilidad
if nmap.is_available():
    print("✅ Nmap disponible")
    
    # Escaneo rápido
    results = nmap.quick_scan("scanme.nmap.org")
    
    # Obtener resumen
    summary = nmap.get_open_ports_summary(results)
    
    # Mostrar resultados
    print(f"\nPuertos abiertos: {len(summary)}")
    for port in summary:
        print(f"  - {port['port']}/{port['protocol']}: {port['service']}")
    
    # Exportar
    nmap.export_results(results, "nmap_results.json")
    print("\n✅ Resultados exportados")
else:
    print("❌ Nmap no disponible")
```

### Salida
```
✅ Nmap disponible

Puertos abiertos: 3
  - 22/tcp: ssh
  - 80/tcp: http
  - 443/tcp: https

✅ Resultados exportados
```

## 📊 Ejemplo 8: Tests Automatizados

```bash
python tests/test_nmap_integration.py
```

### Salida
```
============================================================
PRUEBAS DE INTEGRACIÓN DE NMAP
============================================================

Estas pruebas utilizan scanme.nmap.org, un servidor
de pruebas oficial proporcionado por el proyecto Nmap.
============================================================

============================================================
TEST 1: Verificar disponibilidad de Nmap
============================================================
✅ Nmap está disponible y funcional

============================================================
TEST 2: Escaneo Rápido de Puertos Comunes
============================================================

Objetivo: scanme.nmap.org
Nota: Este es un servidor de pruebas oficial de Nmap

Ejecutando escaneo rápido...
✅ Escaneo completado

Puertos abiertos encontrados: 3
  - Puerto 22/tcp: ssh OpenSSH 6.6.1p1
  - Puerto 80/tcp: http Apache httpd 2.4.7
  - Puerto 443/tcp: https Apache httpd 2.4.7

============================================================
TEST 3: Módulo PortScanModule Completo
============================================================

Objetivo: http://scanme.nmap.org

Ejecutando módulo de escaneo...

✅ Módulo ejecutado: 3 hallazgos

Hallazgos por severidad:
  - INFO: 2
  - MEDIUM: 1

Ejemplos de hallazgos:

  1. Puerto Abierto: 22/tcp - ssh (OpenSSH 6.6.1p1)
     Severidad: medium
     Puerto: 22/tcp
     Servicio: ssh

  2. Puerto Abierto: 80/tcp - http (Apache httpd 2.4.7)
     Severidad: info
     Puerto: 80/tcp
     Servicio: http

  3. Puerto Abierto: 443/tcp - https (Apache httpd 2.4.7)
     Severidad: info
     Puerto: 443/tcp
     Servicio: https

============================================================
TEST 4: Detección de Servicios y Versiones
============================================================

Objetivo: scanme.nmap.org

Ejecutando escaneo de servicios en puertos comunes...
✅ Escaneo de servicios completado

Servicios detectados: 3

  Puerto 22/tcp:
    Servicio: ssh - OpenSSH 6.6.1p1

  Puerto 80/tcp:
    Servicio: http - Apache httpd 2.4.7

  Puerto 443/tcp:
    Servicio: https - Apache httpd 2.4.7

============================================================
PRUEBAS COMPLETADAS
============================================================

Para usar Nmap en tu proyecto:
  python run.py https://tu-objetivo.com --nmap

Para más información:
  Ver docs/NMAP_INTEGRATION.md
============================================================
```

## 📝 Notas Importantes

1. **Servidor de Pruebas**: Todos los ejemplos usan `scanme.nmap.org`, servidor oficial de Nmap
2. **Permisos**: Algunos escaneos requieren privilegios de administrador
3. **Tiempo**: Los tiempos de escaneo varían según el tipo y número de puertos
4. **Legalidad**: Solo escanea sistemas autorizados

## 🔗 Referencias

- [Documentación Completa](NMAP_INTEGRATION.md)
- [Resumen Técnico](NMAP_SUMMARY.md)
- [Guía de Integración](NMAP_RUN_PY_INTEGRATION.md)
- [Tests](../tests/test_nmap_integration.py)
