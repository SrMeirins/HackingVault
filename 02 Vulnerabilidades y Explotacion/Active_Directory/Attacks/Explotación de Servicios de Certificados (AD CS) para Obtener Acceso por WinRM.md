# Explotación de Servicios de Certificados de Active Directory (AD CS) para Obtener Acceso por WinRM

> **⚠️ ¡Advertencia!¡Acceso Credencializado Necesario!**  
> Este ataque requiere acceso a Microsoft Active Directory Certificate Services (AD CS) y credenciales válidas para autenticarse. Con este acceso, podemos obtener un certificado de autenticación que nos permitirá acceder remotamente a sistemas a través de WinRM, lo que podría resultar útil en un entorno donde no se permite el acceso tradicional mediante usuario y contraseña.

## Pasos para la Explotación

1. **Acceso a la Consola de Servicios de Certificados de Active Directory (AD CS)**

   Una vez tengamos acceso al servidor de AD CS, debemos dirigirnos a la siguiente URL en el navegador:
   
   ```
   http://ip/certsrv
   ```

   Esto nos llevará a la interfaz de **Request a Certificate**. Si tenemos las credenciales adecuadas, podemos solicitar un certificado de autenticación.

2. **Solicitud de un Certificado mediante un "Advanced Certificate Request"**

   En el panel de **Advanced Certificate Request**, seleccionamos la opción para crear un **Certificate Request**. Para ello, vamos a necesitar generar un archivo de solicitud de certificado junto con una clave privada.

3. **Generación de la Solicitud de Certificado**

   Usaremos OpenSSL para crear una solicitud de certificado y una clave privada. El comando sería el siguiente:
   
   ```bash
   openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr
   ```

   Esto generará dos archivos:
   - **amanda.key**: La clave privada.
   - **amanda.csr**: La solicitud del certificado.

4. **Subir la Solicitud de Certificado a la Interfaz Web**

   Ahora debemos copiar el contenido del archivo **amanda.csr** y pegarlo en la interfaz web de AD CS. Esto nos proporcionará un archivo **.cer**, que es el certificado que vamos a usar junto con la clave privada.

5. **Autenticación con el Certificado a través de WinRM**

   Usamos el archivo **.cer** y la clave privada **amanda.key** para autenticar nuestra sesión en el servidor de destino a través de **WinRM**. Para esto, utilizamos la herramienta **Evil-WinRM**.

   Si intentamos autenticarnos con usuario y contraseña (sabiendo que el usuario está en el grupo de **Remote Management Users**) pero nos da error, podemos usar el certificado junto con la clave privada para autenticar la sesión. El comando sería el siguiente:

   ```bash
   evil-winrm -S -c certnew.cer -k amanda.key -i 10.10.10.103 -u 'amanda' -p 'Ashare1972'
   ```

Este ataque nos permite obtener acceso a través de WinRM utilizando un certificado generado a partir de AD CS, eludiendo restricciones de autenticación tradicional.
