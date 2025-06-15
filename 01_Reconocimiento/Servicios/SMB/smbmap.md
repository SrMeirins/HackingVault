# Uso de SMBMap para Reconocimiento SMB

**SMBMap** es una herramienta útil para interactuar con servidores SMB. Permite realizar tareas como la enumeración de recursos compartidos, acceso a ellos, y la descarga de archivos. Es especialmente útil para obtener información sobre recursos y permisos en servidores Windows.

## Comandos Básicos

- **Conexión a un servidor SMB:**

  ```bash
  smbmap -H <ip>
  ```

  - **`<ip>`**: Dirección IP del servidor SMB.

- **Acceder como usuario invitado si no se muestran recursos:**

  ```bash
  smbmap -H <ip> -u 'guest'
  ```

  - **`-u 'guest'`**: Utiliza el usuario invitado para la autenticación en el servidor SMB, útil si no se listan recursos de otro modo.

- **Listar los recursos compartidos de manera recursiva:**

  ```bash
  smbmap -H <ip> -r <recurso>
  ```

  - **`-r <recurso>`**: Lista los contenidos de un recurso compartido de forma recursiva.

- **Descargar un recurso específico:**

  ```bash
  smbmap -H <ip> --download <recurso>
  ```

  - **`--download <recurso>`**: Permite descargar un archivo o directorio desde el recurso compartido especificado.
