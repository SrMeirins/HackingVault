## **Ruta Sugerida**: `03_Post_Explotacion/Movimiento_Lateral/Kerberos_Guia_Completa.md`

# **Guía Completa de Autenticación Kerberos para Pentesting (Windows y Linux)**

Encontrar un servicio como SSH que rechaza la autenticación por contraseña y exige GSSAPI es un claro indicativo de un entorno Kerberizado. Comprender y configurar el cliente Kerberos es una habilidad esencial para moverse en redes corporativas, ya que este protocolo es el estándar de facto tanto en **Active Directory (Windows)** como en muchas implementaciones de **Linux**.

## 1\. ¿Es lo Mismo para Windows y Linux?

**Sí, el protocolo Kerberos es un estándar universal.** La configuración del cliente (`/etc/krb5.conf`) y los comandos (`kinit`, `klist`) que se utilizan en una máquina Linux son los mismos, independientemente de si el **KDC (Key Distribution Center)** es un **Controlador de Dominio de Windows** o un servidor **MIT Kerberos en Linux**.

  * **Active Directory**: Utiliza Kerberos como su principal protocolo de autenticación. Cada Controlador de Dominio actúa como un KDC.
  * **Linux**: Implementaciones como MIT Kerberos o Heimdal proporcionan la misma funcionalidad de KDC.

Por lo tanto, las técnicas descritas aquí son aplicables a ambos entornos.

## 2\. Análisis a Fondo del Archivo `/etc/krb5.conf`

Este archivo es el cerebro del cliente Kerberos. Un error aquí es la causa del 99% de los fallos de autenticación. Analicemos cada directiva en detalle.

```ini
[libdefaults]
  # Define el "reino" Kerberos por defecto si no se especifica otro.
  # Es una buena práctica para evitar tener que escribir @REALM.HTB constantemente.
  default_realm = REALCORP.HTB

  # Permite al cliente usar DNS para descubrir el realm de un host.
  # Si es 'true', el cliente puede resolver que "servidor.realcorp.htb" pertenece a "REALCORP.HTB".
  dns_lookup_realm = true

  # Permite al cliente usar DNS (registros SRV _kerberos._tcp) para localizar los KDCs.
  # Si el DNS del entorno está bien configurado, esto elimina la necesidad de definirlos manualmente.
  dns_lookup_kdc = true

  # Deshabilita la búsqueda inversa de DNS (IP -> Hostname). Se desactiva por seguridad
  # y rendimiento, para evitar que el cliente sea engañado por un registro PTR falso.
  rdns = false

  # Permite que los tickets obtenidos sean "forwardables" (reenviables).
  # CRUCIAL para pentesting: Te permite autenticarte en un servidor y, desde ese
  # servidor, usar tu mismo ticket para autenticarte en un tercer sistema (pivoting).
  forwardable = true

[realms]
  # Esta sección actúa como una "libreta de direcciones" manual para los KDCs,
  # especialmente útil si 'dns_lookup_kdc' falla o está deshabilitado.
  REALCORP.HTB = {
    # Define explícitamente la dirección del KDC. Puede haber varias líneas 'kdc'
    # para redundancia. En Active Directory, todos los DCs son KDCs.
    kdc = srv01.realcorp.htb

    # Opcional: Define el servidor para cambios de contraseña (usado por el comando kpasswd).
    admin_server = srv01.realcorp.htb
  }

[domain_realm]
  # Mapea dominios y subdominios DNS a realms de Kerberos.
  # Esto le dice al cliente qué realm usar para un host específico.

  # El punto inicial ('.') actúa como un comodín. Cualquier host que termine
  # en ".realcorp.htb" será mapeado al realm REALCORP.HTB.
  .realcorp.htb = REALCORP.HTB

  # Mapea el dominio raíz.
  realcorp.htb = REALCORP.HTB
```

## 3\. El Proceso de Autenticación: `kinit` y `klist`

### `kinit`: Obtener el Pasaporte del Dominio (TGT)

`kinit` es el comando que inicia el proceso. Su única función es contactar al KDC (que encontró gracias al `krb5.conf`) y solicitar un **Ticket-Granting Ticket (TGT)**.

Piénsalo como la entrada a un parque de atracciones:

1.  Vas a la taquilla (`kinit` contactando al KDC).
2.  Presentas tu identificación y pagas (`usuario` y `contraseña`).
3.  Te dan una pulsera (`TGT`) que prueba que has entrado legalmente.

<!-- end list -->

```bash
kinit j.nakazawa
```

Este comando solicitará la contraseña de `j.nakazawa` y, si es correcta, almacenará el TGT en un archivo caché.

### `klist`: Revisar tus Tickets

`klist` te permite ver los "pasaportes" (tickets) que tienes.

```bash
klist
```

**Salida Detallada:**

```
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: j.nakazawa@REALCORP.HTB

Valid starting     Expires              Service principal
05/08/25 17:54:02  06/08/25 17:54:01    krbtgt/REALCORP.HTB@REALCORP.HTB
```

  * **`Ticket cache`**: La ruta al archivo donde se guarda tu ticket.
  * **`Default principal`**: Tu identidad kerberizada (`usuario@REALM`).
  * **`Service principal`**: El servicio para el que es válido este ticket.
      * **`krbtgt/REALCORP.HTB@REALCORP.HTB`**: Este no es un ticket cualquiera, es **el TGT**. Es un ticket para el "Servicio de Emisión de Tickets" (`krbtgt`). Tenerlo te autoriza a pedir tickets para otros servicios (SSH, SMB, HTTP) sin volver a usar tu contraseña. Con la pulsera del parque, ahora puedes ir a cada atracción y pedir un ticket específico para montar.

## 4\. El Acceso Final

Con un TGT válido en tu caché, el sistema operativo se encarga del resto. Al intentar conectar por SSH, el cliente negociará automáticamente la autenticación GSSAPI/Kerberos.

```bash
ssh j.nakazawa@srv01.realcorp.htb
```

El cliente SSH usará tu TGT para solicitar al KDC un **Ticket de Servicio** para el servicio `host/srvpod01.realcorp.htb`. Luego presentará ese ticket de servicio al servidor SSH, que lo validará y te concederá acceso. Todo esto de forma transparente y sin solicitarte la contraseña de nuevo.