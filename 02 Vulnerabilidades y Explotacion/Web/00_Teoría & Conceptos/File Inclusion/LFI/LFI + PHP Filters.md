Cuando el backend está escrito en PHP y detectamos una LFI, se abre un abanico enorme de posibilidades gracias a los **wrappers de PHP**, especialmente los **php://filters**. Estos permiten leer archivos, manipular flujos y, en fases posteriores, incluso derivar en RCE.

Aquí tienes un resumen práctico de cómo aprovecharlos para **leer código fuente** en sistemas con LFI.

---

# **1. Qué son los PHP Wrappers (visión rápida)**

PHP permite acceder a distintos "streams" usando rutas especiales como:

- `php://input`
    
- `php://memory`
    
- `php://stdin`
    
- `php://filter/...`
    

Los desarrolladores los usan para procesar archivos o flujos internos.  
Los pentesters los usan para **romper LFI limitados, leer código fuente y encadenar ataques**.

---

# **2. PHP Filters: el wrapper clave para leer código**

Los filtros se invocan como:

```
php://filter/<opciones>/resource=<archivo>
```

Las dos partes que interesan para explotación son:

- **resource=** → indica qué archivo se debe leer
    
- **read=convert.base64-encode** → codifica la salida en Base64 evitando la ejecución del PHP
    

Este filtro es oro porque:

- evita que el archivo se ejecute como PHP
    
- te entrega el **código fuente en Base64**, que luego decodificas
    
- funciona incluso cuando la app **agrega `.php` automáticamente**
    

---

# **3. Fase previa: enumerar archivos PHP**

Como en una LFI normal, primero hay que descubrir archivos que puedan incluirse.

Ejemplo con **ffuf**:

```
ffuf -w /path/to/wordlist.txt:FUZZ -u http://IP:PUERTO/FUZZ.php
```

✔ Importante: como usas LFI, **no te limites a códigos 200**.  
Incluso archivos que devuelven **302 o 403** pueden ser leídos vía LFI.

Una vez localizados ficheros (por ejemplo: `index.php`, `config.php`), puedes:

- revisarlos uno a uno
    
- buscar rutas adicionales
    
- identificar referencias a otros `.php`
    

Este es el ciclo típico para mapear la app.

---

# **4. Comportamiento normal de LFI al incluir PHP**

Cuando haces:

```
?file=config
```

y el backend ejecuta `include("config.php")`, el resultado suele ser una **página en blanco** (o HTML), porque PHP ejecutó el archivo en lugar de mostrar su contenido.

Para pentesting lo que queremos es el **texto del archivo**, no su ejecución.

---

# **5. Cómo leer el código fuente con `convert.base64-encode`**

Este es el payload estándar para obtener el código fuente:

```
php://filter/read=convert.base64-encode/resource=<archivo>
```

Ejemplo práctico leyendo `config.php`, suponiendo que la app añade `.php` automáticamente:

```
?file=php://filter/read=convert.base64-encode/resource=config
```

La respuesta será un **largo blob Base64**.

Lo decodificamos:

```bash
echo "<BASE64>" | base64 -d
```

Resultado: código PHP original.

### Ejemplo real de lo que encuentras

Fragmentos típicos tras decodificar:

```php
if ($_SERVER['REQUEST_METHOD'] == 'GET' && realpath(__FILE__) == realpath($_SERVER['SCRIPT_FILENAME'])) {
    header('HTTP/1.0 403 Forbidden', TRUE, 403);
    die(header('location: /index.php'));
}
```

Justo lo que querías: **configuración interna, rutas, funciones, credenciales, lógica de la aplicación…**

---

# **6. Consejos prácticos (muy importantes)**

✔ **Copiar el Base64 completo**  
Cualquier carácter faltante = rotura al decodificar. Mejor usar “ver código fuente” del navegador.

✔ **Si la app añade `.php`, es perfecto**  
El filtro aún lo acepta y funciona como:  
`resource=config.php`

✔ **Si encuentras includes internos**, ve siguiendo la cadena  
`include "./lib/db.php"` → siguiente archivo que debes leer.

✔ **Funciona también para bugs tipo XXE o SSRF**  
Siempre que la función subyacente ejecute o lea archivos locales, los filtros son válidos.