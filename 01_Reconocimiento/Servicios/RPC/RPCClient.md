# Uso de rpcclient para Enumeración en Active Directory

**Remote Procedure Call (RPC)** es un protocolo que permite a un programa ejecutar una función en un servidor remoto como si fuera una función local. En entornos Windows, RPC es ampliamente utilizado para diversas operaciones administrativas y de red. En Linux, la herramienta **rpcclient** forma parte del paquete Samba y permite interactuar con servicios RPC de un servidor Windows, facilitando tareas de enumeración y administración de un dominio Active Directory (AD).

## ¿Qué es rpcclient?

- **rpcclient** es una herramienta de línea de comandos en Linux que forma parte del paquete Samba.
- Permite ejecutar comandos remotos en servidores Windows a través del protocolo RPC.
- Se utiliza para obtener información y realizar operaciones administrativas en un dominio, como enumerar usuarios, grupos y otras configuraciones del sistema.

## Cómo Funciona la Conexión

La conexión se establece mediante la comunicación con el servicio RPC del servidor Windows. Esto se puede hacer de dos formas:

- **Con Credenciales Válidas:**  
  Se provee un nombre de usuario y contraseña en el formato `"usuario%contraseña"`, lo que permite autenticarse y ejecutar comandos con privilegios asociados a esa cuenta.
  
- **Con NULL Session:**  
  En algunos casos, es posible conectarse sin credenciales, lo que se conoce como una "NULL Session". Esto permite ejecutar ciertos comandos limitados en el servidor, aprovechando configuraciones débiles de seguridad.

Una vez establecida la conexión, **rpcclient** envía comandos RPC al servidor para recuperar información o ejecutar acciones específicas. Entre las operaciones comunes se encuentra la enumeración de usuarios, grupos y otros objetos del dominio.

## Comandos de Ejemplo

### Conexión al Servidor SMB

- **Con autenticación (usuario y contraseña):**

  ```bash
  rpcclient -U "user%password" <ip>
  ```

- **Conexión usando una NULL Session (sin credenciales):**

  ```bash
  rpcclient -U "" <ip> -N
  ```

### Enumeración de Información del Dominio

- **Enumerar usuarios del dominio:**

  ```bash
  rpcclient -U "user%password" <ip> -c 'enumdomusers'
  ```

- **Enumerar grupos del dominio:**

  ```bash
  rpcclient -U "user%password" <ip> -c 'enumdomgroups'
  ```

- **Enumerar miembros de un grupo (reemplazar `rid` por el identificador del grupo):**

  ```bash
  rpcclient -U "user%password" <ip> -c 'querygroupmem rid'
  ```

- **Obtener información de un usuario (reemplazar `rid` por el identificador del usuario):**

  ```bash
  rpcclient -U "user%password" <ip> -c 'queryuser rid'
  ```

- **Obtener descripciones de usuarios del dominio:**

  ```bash
  rpcclient -U "user%password" <ip> -c 'querydispinfo'
  ```
