# **Análisis Post-Explotación: Credenciales en el archivo `.msmtprc`**

Durante la fase de post-explotación, uno de los objetivos principales es la búsqueda de credenciales que permitan el movimiento lateral o la escalada de privilegios. Un lugar común para encontrar credenciales en texto plano son los archivos de configuración de aplicaciones, y `.msmtprc` es un ejemplo perfecto de ello.

## 1\. ¿Qué es el archivo `.msmtprc`?

El archivo `.msmtprc` es el fichero de configuración para **msmtp**, un cliente SMTP ligero y sencillo. Su función es permitir a los usuarios y a las aplicaciones enviar correos electrónicos desde la línea de comandos sin necesidad de configurar un servidor de correo local completo como Postfix o Sendmail.

Se utiliza comúnmente para:

  * Notificaciones del sistema.
  * Scripts que necesitan enviar correos electrónicos.
  * Reemplazar el comando `/usr/sbin/sendmail` en un sistema.

Desde una perspectiva de seguridad, su principal característica de interés es que necesita almacenar las credenciales de un servidor SMTP para poder autenticarse y enviar correos, y estas credenciales a menudo se guardan en texto plano.

## 2\. Análisis del Archivo de Configuración (Caso Práctico)

A continuación, se desglosa el contenido de un archivo `.msmtprc` encontrado en el directorio `/home/j.nakazawa`.

**Contenido del archivo:**

```
# Set default values for all following accounts.
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /dev/null

# RealCorp Mail
account        realcorp
host           127.0.0.1
port           587
from           j.nakazawa@realcorp.htb
user           j.nakazawa
password       sJB}RM>6Z~64_
tls_fingerprint    C9:6A:B9:F6:0A:D4:9C:2B:B9:F6:44:1F:30:B8:5E:5A:D8:0D:A5:60

# Set a default account
account default : realcorp
```

### **Inteligencia Obtenida:**

  * **Credenciales en Texto Plano**: La directiva `password` revela la contraseña del usuario `j.nakazawa` sin ningún tipo de cifrado.
      * **Usuario**: `j.nakazawa`
      * **Contraseña**: `sJB}RM>6Z~64_`
  * **Servidor SMTP**: La configuración apunta a un servidor SMTP en `host 127.0.0.1` en el puerto `587`.
  * **Contexto de la Configuración**: La salida del comando `ss -talpen` (que muestra los sockets de red) confirma que hay un servicio escuchando en `127.0.0.1:587`. Esto indica que el propio servidor comprometido está corriendo un servicio de envío de correo (probablemente el mismo OpenSMTPD) que requiere autenticación, y el usuario `j.nakazawa` está configurado para usarlo.
  * **Nombre de Usuario y Dominio**: Se confirma el formato de los nombres de usuario (`j.nakazawa`) y el dominio de correo (`realcorp.htb`).

## 3\. Implicaciones de Seguridad y Siguientes Pasos

El descubrimiento de estas credenciales es un avance crítico en un pentest.

  * **Reutilización de Contraseñas**: El primer paso inmediato es intentar reutilizar estas credenciales (`j.nakazawa:sJB}RM>6Z~64_`) en otros servicios encontrados en la red, como:

      * SSH (puerto 22)
      * SMB (puerto 445)
      * WinRM (puerto 5985)
      * Cualquier panel de administración web.
        Los usuarios a menudo reutilizan contraseñas en múltiples sistemas, y este podría ser el caso.

  * **Acceso al Correo**: Aunque el servidor SMTP esté en `localhost`, si se encuentra una manera de interactuar con él (por ejemplo, a través de otra aplicación en el mismo servidor), se podrían usar estas credenciales para enviar correos haciéndose pasar por el usuario, lo que podría ser útil para ataques de phishing internos.

  * **Escalada de Privilegios**: Si el usuario `j.nakazawa` tiene permisos `sudo` o pertenece a grupos privilegiados, estas credenciales podrían conducir directamente a una escalada de privilegios en el sistema actual.

En resumen, la presencia de un archivo `.msmtprc` debe ser tratada como un hallazgo de alta prioridad. Su análisis proporciona credenciales directas y un valioso contexto sobre la infraestructura de correo de la organización.