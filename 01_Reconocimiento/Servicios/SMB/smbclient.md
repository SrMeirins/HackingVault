# Uso de smbclient para Reconocimiento en SMB

**smbclient** es una herramienta de línea de comandos que forma parte del paquete Samba y permite interactuar con recursos compartidos en redes Windows a través del protocolo SMB. Es muy útil para realizar tareas de reconocimiento, como listar recursos disponibles en un servidor o acceder a carpetas compartidas utilizando sesiones NULL.

## Comandos Básicos

- **Listar recursos compartidos usando una NULL Session:**

  ```bash
  smbclient -L <ip> -N
  ```

  - **`-L <ip>`**: Lista los recursos compartidos disponibles en el servidor identificado por `<ip>`.
  - **`-N`**: Indica que se utiliza una NULL Session, es decir, sin autenticación.

- **Acceder a una carpeta específica con una NULL Session:**

  ```bash
  smbclient "//10.10.10.103/Department Shares" -N
  ```

  - **`"//10.10.10.103/Department Shares"`**: Es la ruta al recurso compartido al que se desea acceder.
  - **`-N`**: Se utiliza para conectarse sin necesidad de credenciales, aprovechando una NULL Session.
```
