# Servidor Flask - Visualización de Reportes

## Descripción

El servidor Flask (`app.py`) proporciona una interfaz web para visualizar los reportes generados por el framework WebSec.

## Características

- 🏠 **Página Principal**: Dashboard con acceso a todos los reportes
- 🌳 **Árbol de Crawling**: Visualización interactiva del árbol de navegación
- 📊 **Reportes HTML**: Acceso directo a los reportes de vulnerabilidades
- 🔄 **Auto-detección**: Detecta automáticamente el último escaneo

## Uso

### 1. Iniciar el Servidor

```bash
python app.py
```

El servidor se iniciará en `http://localhost:5000/`

### 2. Acceder a los Reportes

#### Página Principal
```
http://localhost:5000/
```

Muestra:
- Información del último escaneo
- Enlaces a árbol de crawling
- Enlaces a reporte de vulnerabilidades

#### Árbol de Crawling
```
http://localhost:5000/crawl_tree
```

Visualización interactiva del árbol de navegación con D3.js:
- Nodos expandibles/colapsables
- Tooltips con información completa
- Ctrl+Click para abrir URLs en nueva pestaña

#### Reporte de Vulnerabilidades
```
http://localhost:5000/reports/scan_TIMESTAMP/vulnerability_report.html
```

Reporte HTML profesional con:
- Dashboard con métricas
- Gráficos interactivos
- Tabla de vulnerabilidades
- Detalles expandibles

### 3. API Endpoints

#### GET `/api/crawl_tree/<scan_id>`
Devuelve el JSON del árbol de crawling para un escaneo específico.

**Ejemplo:**
```bash
curl http://localhost:5000/api/crawl_tree/scan_20260216_131600
```

**Respuesta:**
```json
{
  "https://example.com/": [
    "https://example.com/about",
    "https://example.com/contact"
  ],
  "https://example.com/about": [],
  "https://example.com/contact": []
}
```

#### GET `/reports/<path:filename>`
Sirve archivos estáticos del directorio `reports/`.

**Ejemplo:**
```bash
curl http://localhost:5000/reports/scan_20260216_131600/vulnerability_report.html
```

## Estructura de URLs

```
/                                           → Página principal
/crawl_tree                                 → Redirige al último escaneo
/crawl_tree/<scan_id>                       → Árbol de crawling específico
/api/crawl_tree/<scan_id>                   → JSON del árbol (API)
/reports/<scan_id>/<filename>               → Archivos de reporte
```

## Manejo de Errores

### Error: "No hay escaneos disponibles"

**Causa**: No existe ningún directorio de escaneo en `reports/`.

**Solución**: Ejecuta un escaneo primero:
```bash
python run.py https://example.com
```

### Error: "crawl_tree.json no encontrado"

**Causa**: El escaneo se ejecutó con `--no-crawl`.

**Solución**: Ejecuta un nuevo escaneo sin esa opción:
```bash
python run.py https://example.com
```

### Error: "404 Not Found"

**Causa**: La ruta solicitada no existe.

**Solución**: Verifica que el scan_id sea correcto y que los archivos existan en el directorio de reportes.

## Configuración

### Puerto Personalizado

Edita `app.py` y cambia el puerto:

```python
if __name__ == '__main__':
    port = 8080  # Cambiar aquí
    app.run(port=port, debug=True)
```

### Modo Debug

Por defecto, el servidor corre en modo debug. Para producción, desactívalo:

```python
app.run(port=port, debug=False)
```

### Host Externo

Para acceder desde otras máquinas en la red:

```python
app.run(host='0.0.0.0', port=port, debug=False)
```

⚠️ **Advertencia**: Solo usa `host='0.0.0.0'` en redes confiables.

## Desarrollo

### Agregar Nuevos Endpoints

```python
@app.route('/api/nuevo_endpoint')
def nuevo_endpoint():
    # Tu código aquí
    return jsonify({'status': 'ok'})
```

### Servir Archivos Adicionales

```python
@app.route('/archivos/<path:filename>')
def archivos(filename):
    return send_from_directory('mi_directorio', filename)
```

## Troubleshooting

### El servidor no inicia

**Error**: `Address already in use`

**Solución**: El puerto 5000 está ocupado. Cambia el puerto o mata el proceso:

```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:5000 | xargs kill -9
```

### Los archivos JSON no se cargan

**Problema**: CORS o rutas incorrectas.

**Solución**: Verifica que:
1. El servidor Flask esté corriendo
2. La ruta del JSON sea correcta
3. El archivo exista en el directorio de reportes

### El árbol de crawling no se muestra

**Problema**: JavaScript no puede cargar el JSON.

**Solución**:
1. Abre la consola del navegador (F12)
2. Verifica errores en la pestaña "Console"
3. Verifica que la petición a `/api/crawl_tree/<scan_id>` devuelva 200 OK

## Mejoras Futuras

- [ ] Autenticación con JWT
- [ ] Comparación de escaneos
- [ ] Exportación de reportes en múltiples formatos
- [ ] Búsqueda y filtrado avanzado
- [ ] Notificaciones en tiempo real
- [ ] Integración con bases de datos
- [ ] API REST completa

## Referencias

- [Flask Documentation](https://flask.palletsprojects.com/)
- [D3.js Documentation](https://d3js.org/)
- [Chart.js Documentation](https://www.chartjs.org/)

---

**Última actualización**: 2026-02-16
