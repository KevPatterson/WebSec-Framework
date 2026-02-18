# 🚀 Guía Rápida - Servidor Flask

## ⚠️ PROBLEMA COMÚN: Error 404 al cargar el árbol

Si obtienes un error 404 al intentar ver el árbol de crawling, es porque:

1. **El servidor Flask está corriendo una versión antigua del código**
2. **Necesitas reiniciar el servidor**

## ✅ SOLUCIÓN RÁPIDA

### Windows:

1. **Detén el servidor Flask actual:**
   - Ve a la terminal donde está corriendo
   - Presiona `Ctrl + C`
   - O cierra la terminal

2. **Inicia el servidor actualizado:**
   ```cmd
   start_server.bat
   ```
   
   O manualmente:
   ```cmd
   python app.py
   ```

3. **Abre tu navegador:**
   ```
   http://localhost:5000/
   ```

### Linux/Mac:

1. **Detén el servidor Flask actual:**
   ```bash
   # Encuentra el proceso
   lsof -ti:5000
   
   # Mátalo
   kill -9 $(lsof -ti:5000)
   ```

2. **Inicia el servidor actualizado:**
   ```bash
   python app.py
   ```

3. **Abre tu navegador:**
   ```
   http://localhost:5000/
   ```

## 🔍 Verificar que Todo Funciona

Ejecuta el script de prueba:

```bash
python test_flask_server.py
```

Deberías ver:
```
✅ TODAS LAS PRUEBAS PASARON
```

## 📊 URLs Disponibles

Una vez que el servidor esté corriendo correctamente:

| Descripción | URL |
|-------------|-----|
| Página Principal | http://localhost:5000/ |
| Árbol de Crawling | http://localhost:5000/crawl_tree |
| Último Reporte | http://localhost:5000/reports/scan_TIMESTAMP/vulnerability_report.html |
| API JSON | http://localhost:5000/api/crawl_tree/scan_TIMESTAMP |

## 🐛 Troubleshooting

### Error: "Address already in use"

**Problema:** El puerto 5000 ya está ocupado.

**Solución:**
```cmd
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Linux/Mac
lsof -ti:5000 | xargs kill -9
```

### Error: "No hay escaneos disponibles"

**Problema:** No has ejecutado ningún escaneo.

**Solución:**
```bash
python run.py https://example.com
```

### Error: "crawl_tree.json no encontrado"

**Problema:** El escaneo se ejecutó con `--no-crawl`.

**Solución:**
```bash
python run.py https://example.com
# (sin --no-crawl)
```

### El árbol no se muestra (pantalla en blanco)

**Problema:** JavaScript no puede cargar el JSON.

**Solución:**
1. Abre la consola del navegador (F12)
2. Ve a la pestaña "Console"
3. Busca errores en rojo
4. Verifica que la URL sea correcta: `/crawl_tree/scan_TIMESTAMP`

## 📝 Notas Importantes

1. **Siempre reinicia el servidor** después de actualizar el código
2. **Usa Ctrl+C** para detener el servidor limpiamente
3. **Verifica que el puerto 5000** esté libre antes de iniciar
4. **Ejecuta escaneos CON crawling** para ver el árbol

## 🎯 Flujo de Trabajo Recomendado

```
1. Ejecutar escaneo
   → python run.py https://example.com

2. Iniciar servidor
   → python app.py

3. Abrir navegador
   → http://localhost:5000/

4. Ver reportes
   → Click en los botones de la página principal
```

---

**¿Sigues teniendo problemas?**

Ejecuta el diagnóstico completo:
```bash
python test_flask_server.py
```

Y comparte el resultado para obtener ayuda específica.
