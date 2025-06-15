# Uso de NXC para Reconocimiento en SMB

**NXC** es una herramienta que permite realizar diversas tareas de reconocimiento y explotación a través de redes SMB, facilitando la interacción con recursos compartidos de servidores Windows. Se puede utilizar para verificar credenciales, listar recursos compartidos y obtener información sobre permisos.

## Comandos Básicos

- **Conexión a un servidor SMB sin credenciales:**

  ```bash
  nxc smb <ip>
  ```

  - **`<ip>`**: Dirección IP del servidor SMB al que se desea conectar.

- **Verificar si las credenciales proporcionadas son correctas:**

  ```bash
  nxc smb <ip> -u 'user' -p 'password'
  ```

  - **`-u 'user'`**: Nombre de usuario para la autenticación.
  - **`-p 'password'`**: Contraseña del usuario especificado.
  
- **Listar recursos compartidos disponibles para el usuario y verificar permisos:**

  ```bash
  nxc smb <ip> -u 'user' -p 'password' --shares
  ```

  - **`--shares`**: Muestra los recursos compartidos disponibles en el servidor SMB para el usuario autenticado y los permisos asociados.
