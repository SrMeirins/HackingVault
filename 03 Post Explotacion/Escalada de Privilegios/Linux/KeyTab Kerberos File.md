# **Guía Definitiva: Dominación de Dominios Kerberos a través del Compromiso de `keytab`**

En la jerarquía de los tesoros de un pentester, un archivo `keytab` legible es el equivalente a encontrar las llaves del reino. No es simplemente una contraseña; es un mecanismo de confianza que, si se compromete, permite a un atacante no solo suplantar servicios, sino tomar el control administrativo total del dominio Kerberos.

## **Parte 1: El Fundamento Teórico - La Arquitectura de Confianza de Kerberos**

### **1.1 Desmitificando el Archivo `keytab`: Las Llaves de Cada Puerta**

Para explotar un `keytab`, es vital entender que **no es un archivo único y centralizado**.

  * **Definición Técnica**: Un `keytab` (`Key Table`) es un archivo local que contiene las **claves secretas** (esencialmente, las "contraseñas") de uno o más **principales de Kerberos**.

  * **Analogía: Un Edificio de Alta Seguridad**:

      * **El KDC (Key Distribution Center)**: Es la **sala de control central**. Almacena la identidad y la clave secreta de cada empleado (usuario) y de cada puerta con lector de tarjeta (servicio) del edificio.
      * **Los Servidores (SSH, Web, etc.)**: Son las **puertas con lector de tarjeta**. Cada puerta (`srv01`, `srv02`, etc.) necesita su propia llave de identidad para funcionar y comunicarse de forma segura con la sala de control.
      * **El Archivo `keytab`**: El archivo `/etc/krb5.keytab` en `srv01` es la **llave de identidad de esa puerta específica**. Le permite descifrar los "pases de un solo uso" (tickets de servicio) que la sala de control emite para los usuarios que quieren acceder a ella.

Por lo tanto, **cada servidor que ofrece un servicio kerberizado tiene su propio archivo `keytab` local**. El compromiso de un `keytab` en un servidor específico otorga, en principio, control sobre los servicios de *ese* servidor.

### **1.2 La Vulnerabilidad Crítica: Contenido Anormal en un `keytab`**

El problema de seguridad no es la existencia de un `keytab`, sino **su contenido y sus permisos**.

  * **Configuración Segura**: El `keytab` de `srv01` solo debería contener la clave para su propio principal de host (ej. `host/srv01.realcorp.htb@REALCORP.HTB`).
  * **Configuración Catastrófica (Tu Escenario)**: El `keytab` de `srv01` contiene, además de su propia clave, la clave de un principal administrativo (`kadmin/admin@REALCORP.HTB`).

Volviendo a la analogía, esto es como si el técnico, al instalar el lector de tarjetas en una puerta, hubiera dejado pegada en él **una copia de la llave de la sala de control central**. Al encontrar esa llave, no solo puedes abrir esa puerta, sino que ahora puedes administrar la seguridad de todo el edificio.

### **1.3 Anatomía de un Principal de Kerberos**

Un principal es una identidad única (`primario/instancia@REALM`).

  * **`host/srv01.realcorp.htb@REALCORP.HTB`**: La identidad de la **máquina `srv01`**. Permite al sistema operativo autenticarse.
  * **`kadmin/admin@REALCORP.HTB`**: La identidad del **servicio de administración de Kerberos (`kadmin`)** con el rol de **administrador (`admin`)**. Es una cuenta de superusuario para el propio KDC.

## **Parte 2: La Explotación, Detallada al Máximo**

El ataque se basa en una premisa simple: si puedes **leer** el archivo `keytab`, puedes **usar** las claves que contiene para **hacerte pasar** por los principales que están dentro.

### **Paso 2.1: Descubrimiento de la Debilidad (Enumeración)**

El ataque comienza con una simple comprobación de permisos. Como un usuario sin privilegios, se intenta leer el archivo `keytab` usando `klist`.

**Comando de Inspección:**

```bash
# Como un usuario no-root, se intenta listar el contenido del keytab
klist -kt /etc/krb5.keytab
```

Si este comando tiene éxito en lugar de devolver un "Permission denied", la vulnerabilidad está confirmada. La presencia del principal `kadmin/admin` es la señal para proceder.

### **Paso 2.2: Autenticación como Administrador de Kerberos (`kadmin`)**

Ahora, se usará la herramienta `kadmin` para tomar el rol de administrador del KDC.

**Comando de Autenticación:**

```bash
kadmin -kt /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB
```

  * **`-kt /etc/krb5.keytab`**: Instruye a `kadmin`: "No me pidas contraseña. Usa la clave que encuentres para el siguiente principal dentro de este archivo `keytab`".
  * **`-p kadmin/admin@REALCORP.HTB`**: "La identidad que quiero suplantar es la del administrador de `kadmin`".

El resultado es una consola administrativa (`kadmin:`) con control total sobre la base de datos de Kerberos.

### **Paso 2.3: Forjar una Identidad Privilegiada (`root`)**

Desde la consola `kadmin:`, se crea una nueva identidad para el usuario `root` del sistema, asignándole una contraseña que el atacante controla.

**Comando para Añadir un Principal:**

```bash
kadmin: add_principal root
```

`kadmin` solicitará establecer una nueva contraseña para el principal `root@REALCORP.HTB`. Al finalizar, esta identidad existe en el KDC y solo el atacante conoce su clave.

### **Paso 2.4: El Salto Final al Sistema Operativo (`ksu`)**

El último paso es usar la identidad Kerberos recién creada para tomar control del usuario `root` local en el sistema Linux.

**Comando Final de Escalada:**

```bash
# Como el usuario con el que se inició, se ejecuta ksu
ksu
```

  * **`ksu` (Kerberos `su`)** intentará, por defecto, convertirse en `root`.
  * Para ello, solicitará la contraseña del principal **`root@REALCORP.HTB`** (la que se acaba de crear).
  * Tras introducir la contraseña, `ksu` obtiene un ticket de servicio para `root` del KDC, lo valida con el sistema PAM y cambia el UID del proceso a `0`.

El resultado es una shell de `root` completamente funcional, obtenida a partir de un simple permiso de lectura sobre un archivo.

## **Parte 3: Mitigación y Conclusión**

  * **Permisos Estrictos**: El archivo `/etc/krb5.keytab` NUNCA debe ser legible por nadie que no sea `root`. Los permisos correctos son **`600` (`-rw-------`)**, propiedad de `root:root`.
  * **Contenido Mínimo**: Los `keytabs` de los servidores de servicios solo deben contener los principales de los servicios que alojan (generalmente, solo el principal `host/`). **Nunca deben contener principales administrativos (`kadmin`)**.
  * **Auditoría**: Se debe auditar regularmente el contenido y los permisos de todos los archivos `keytab` en la red.