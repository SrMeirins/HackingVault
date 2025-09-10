# **Guía Maestra de Pivoting de Usuario en Linux mediante Abuso de `.k5login`**

En los ecosistemas de red modernos, donde la autenticación centralizada es la norma, Kerberos se erige como el pilar de la seguridad. Sin embargo, su complejidad y las funcionalidades diseñadas para facilitar la administración pueden ser subvertidas para convertirse en potentes vectores de escalada de privilegios. La manipulación del archivo `.k5login` es una de estas técnicas: una maniobra elegante que, si se ejecuta con éxito, permite a un atacante tomar control de una cuenta privilegiada sin necesidad de su contraseña.

## **1. El Fundamento Teórico: `.k5login` y la Delegación de Confianza**

Para explotar un mecanismo, primero es imperativo comprenderlo a fondo.

### **¿Qué es exactamente el archivo `.k5login`?**

El archivo `.k5login` es un componente del módulo de autenticación PAM (Pluggable Authentication Modules) para Kerberos en sistemas Unix/Linux (`pam_krb5`). Su función es establecer una **relación de confianza unidireccional** entre principales de Kerberos.

  * **Analogía Funcional**: Es el equivalente kerberizado del archivo `~/.ssh/authorized_keys` de SSH. Mientras que `authorized_keys` autoriza el acceso mediante claves públicas de SSH, `.k5login` autoriza el acceso mediante **tickets de Kerberos**.

  * **Ubicación y Formato**: Es un archivo de texto plano que debe residir en el directorio `home` del usuario objetivo (ej. `/home/admin/.k5login`). Cada línea del archivo contiene un **principal de Kerberos** completo (`usuario@REALM`).

### **El Flujo de Autenticación Delegada**

Cuando un usuario intenta acceder a una cuenta local (ej. `ssh admin@servidor`), el sistema, a través de PAM, realiza la siguiente comprobación:

1.  El cliente SSH del atacante presenta un ticket de servicio de Kerberos válido, obtenido en nombre del principal del atacante (ej. `atacante@REALM.HTB`).
2.  El servidor SSH recibe este ticket y lo valida.
3.  El módulo `pam_krb5` en el servidor comprueba la existencia del archivo `/home/admin/.k5login`.
4.  Si el archivo existe, el módulo lo lee y busca si el principal del ticket presentado (`atacante@REALM.HTB`) está en la lista.
5.  Si hay una coincidencia, el sistema considera la autenticación exitosa y concede al atacante una shell como el usuario `admin`.

## **2. La Superficie de Ataque: Identificación de Vectores de Escritura**

El ataque se reduce a un único objetivo estratégico: **lograr escribir un archivo `.k5login` controlado por el atacante en el directorio `home` de la víctima**. La creatividad y una enumeración exhaustiva son clave para encontrar el vector que permita esta acción.

### **Vectores de Explotación Comunes**

  * **Permisos de Directorio Inseguros (El error más básico)**:

      * **Causa**: Un administrador configura erróneamente el directorio `/home/admin` con permisos `777` o lo hace propiedad de un grupo al que pertenece el atacante.
      * **Enumeración**: `ls -ld /home/<usuario_victima>`
      * **Probabilidad**: Baja en sistemas bien administrados, pero sorprendentemente común en entornos de desarrollo o mal configurados.

  * **Abuso de Permisos `sudo` (El vector clásico)**:

      * **Causa**: Al atacante se le han concedido permisos de `sudo` para ejecutar comandos que permiten la escritura de archivos, como `mv`, `cp`, `tee`, `chmod`, `chown`, o incluso editores como `vim` o `nano`.
      * **Enumeración**: `sudo -l`
      * **Ejemplo de Explotación con `cp`**:
        ```bash
        echo "atacante@REALM.HTB" > /tmp/.k5login_payload
        sudo -u admin cp /tmp/.k5login_payload /home/admin/.k5login
        ```

  * **Abuso de Lógica de Aplicación o Scripts (El vector elegante)**:

      * **Causa**: Un script (a menudo ejecutado por una tarea `cron` o un `systemd timer`) que se ejecuta como el usuario víctima, realiza operaciones de archivos (copia, movimiento, descompresión) desde una ubicación que el atacante puede controlar.
      * **Enumeración**: Análisis de tareas programadas, auditoría del código fuente de scripts y aplicaciones web que corren en el sistema.
      * **Ejemplo de Explotación**: Un script de backup que ejecuta `tar -xf /backups/new_backup.tar.gz -C /home/admin/`. El atacante podría crear un archivo `.tar.gz` malicioso que contenga un archivo `.k5login` y colocarlo en el directorio de backups.

## **3. Metodología de Explotación Detallada: Paso a Paso**

### **Paso 1: Establecer la Identidad del Atacante (Obtención del TGT)**

Antes de poder delegar confianza, el atacante debe tener su propia identidad validada dentro del dominio Kerberos.

1.  **Configurar el Cliente**: Asegurar que `/etc/krb5.conf` esté correctamente configurado con el `realm` y la dirección del `KDC`.
2.  **Solicitar el Ticket de Otorgamiento de Tickets (TGT)**:
    ```bash
    kinit atacante
    ```
    *Este comando contacta al KDC, intercambia la contraseña del `atacante` por un TGT y lo almacena en una caché local (generalmente `/tmp/krb5cc_UID`).*
3.  **Verificar el TGT**:
    ```bash
    klist
    ```
    *Una salida exitosa mostrará un ticket válido para el servicio `krbtgt/REALM.HTB@REALM.HTB`. Este es el "pasaporte" del atacante.*

### **Paso 2: Crear y Posicionar el Payload (`.k5login`)**

Este es el núcleo del ataque y depende del vector de escritura identificado.

1.  **Crear el archivo de payload**:
    ```bash
    echo "atacante@REALM.HTB" > /tmp/payload.k5login
    ```
2.  **Utilizar el vector de escritura**: Se usa la vulnerabilidad encontrada (permisos de directorio, `sudo`, abuso de script) para mover o crear el archivo `payload.k5login` como `/home/victima/.k5login`.

### **Paso 3: Realizar el Pivoting (El Salto Final)**

Con el `.k5login` en su lugar y un TGT válido para el atacante, el acceso es transparente.

```bash
ssh victima@<IP_o_hostname_del_servidor>
```

**¿Qué ocurre bajo el capó?**

1.  El cliente `ssh` del atacante detecta el TGT cacheado.
2.  Contacta al KDC y dice: "Tengo este TGT para `atacante@REALM.HTB`. Por favor, dame un ticket de servicio para acceder al servicio `host/servidor.REALM.HTB`".
3.  El KDC valida el TGT y emite un ticket de servicio.
4.  El cliente SSH presenta este ticket de servicio al servidor SSH de la víctima.
5.  El servidor SSH, a través de PAM, valida el ticket y luego encuentra `/home/victima/.k5login`. Ve que el principal del ticket (`atacante@REALM.HTB`) está autorizado y concede el acceso.

El atacante obtiene una shell como el usuario `victima` sin haber conocido nunca su contraseña.

## **4. Mitigación y Detección**

  * **Principio de Mínimo Privilegio**: La defensa más efectiva. Los directorios `home` de los usuarios NUNCA deben ser escribibles por otros.
  * **Auditoría Rigurosa de `sudo`**: Limitar los permisos de `sudo` a comandos específicos y evitar aquellos que permiten la escritura arbitraria de archivos.
  * **Monitorización de Creación de Archivos**: Utilizar herramientas de auditoría del sistema de archivos (como `auditd` en Linux) para generar alertas cuando se cree o modifique un archivo `.k5login` en el `home` de un usuario privilegiado.