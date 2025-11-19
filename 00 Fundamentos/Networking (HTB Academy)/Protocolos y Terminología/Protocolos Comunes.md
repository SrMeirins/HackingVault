Los **protocolos de Internet** son reglas estandarizadas (definidas en RFCs) que determinan **cómo los dispositivos se comunican en una red**. Permiten que dispositivos distintos intercambien información de forma **consistente y confiable**, sin importar el hardware o software usado.

Para que los dispositivos se comuniquen, necesitan estar conectados mediante un **canal de comunicación**, que puede ser **cableado** o **inalámbrico**. Sobre este canal, se transmiten los datos usando protocolos estandarizados que definen **el formato y la estructura de la información**.

Los dos tipos principales de conexión en redes son:

- **TCP (Transmission Control Protocol)**: orientado a conexión, confiable.
    
- **UDP (User Datagram Protocol)**: sin conexión, más rápido pero menos confiable.
    

---

## 1️⃣ **Transmission Control Protocol (TCP)**

TCP establece una **conexión virtual** entre dos dispositivos antes de transmitir datos mediante un **Three-Way Handshake**:

1. **SYN**: Cliente solicita conexión.
    
2. **SYN-ACK**: Servidor acepta y confirma.
    
3. **ACK**: Cliente confirma la conexión.
    

> Esta conexión se mantiene hasta que la transferencia de datos finaliza.

**Ejemplo práctico:**  
Cuando accedes a una página web, tu navegador envía una **solicitud HTTP** usando TCP. El servidor responde con el HTML de la página y la conexión se mantiene hasta que toda la información se entrega correctamente.

✅ **Ventaja:** Confiable, garantiza que los datos lleguen completos.  
❌ **Desventaja:** Más lento que UDP por el overhead de conexión.

### Ejemplos de protocolos TCP comunes

|Protocolo|Acrónimo|Puerto|Función|
|---|---|---|---|
|Telnet|Telnet|23|Acceso remoto a texto|
|Secure Shell|SSH|22|Acceso remoto seguro|
|HTTP|HTTP|80|Transferencia de páginas web|
|HTTPS|HTTPS|443|Transferencia de páginas seguras|
|FTP|FTP|20-21|Transferencia de archivos|
|SMTP|SMTP|25|Envío de correos electrónicos|
|POP3|POP3|110|Recuperación de correos|
|IMAP|IMAP|143|Acceso a correos|
|RDP|RDP|3389|Escritorio remoto|
|SMB|SMB|445|Compartir archivos y recursos|
|NFS|NFS|111, 2049|Montaje de sistemas remotos|
|SCP|SCP|22|Copia segura de archivos|
|SIP|SIP|5060|Sesiones VoIP|
|SSL|SSL|443|Transferencia segura de archivos|

> Hay muchos más, incluyendo bases de datos, proxies, RPC, etc.

---

## 2️⃣ **User Datagram Protocol (UDP)**

UDP es **sin conexión**, no establece un canal antes de enviar datos. Solo envía **paquetes al destino** sin verificar si fueron recibidos.

**Ejemplo práctico:**  
Streaming de video (YouTube, Twitch) usa UDP. Algunos paquetes pueden perderse, pero la velocidad es más importante que la confiabilidad. Esto hace que UDP sea más rápido que TCP.

### Protocolos UDP comunes

|Protocolo|Acrónimo|Puerto|Función|
|---|---|---|---|
|DNS|DNS|53|Resolver nombres de dominio|
|TFTP|TFTP|69|Transferencia de archivos simple|
|NTP|NTP|123|Sincronización de relojes|
|SNMP|SNMP|161|Gestión de dispositivos|
|RIP|RIP|520|Intercambio de información de enrutamiento|
|DHCP|DHCP|67, 68|Asignación dinámica de IPs|
|Telnet|TELNET|23|Acceso remoto de texto|
|MySQL|MySQL|3306|Base de datos|
|VNC|VNC|5900|Escritorio remoto gráfico|

---

## 3️⃣ **Internet Control Message Protocol (ICMP)**

ICMP permite que los dispositivos se comuniquen **para diagnóstico y control**, no para transferir datos de usuario.

- **ICMPv4:** para IPv4
    
- **ICMPv6:** para IPv6
    

### Tipos de mensajes ICMP

|Tipo de solicitud|Función|
|---|---|
|Echo Request|Prueba si un dispositivo está activo (ping)|
|Timestamp Request|Consulta hora en dispositivo remoto|
|Address Mask Request|Solicita la máscara de subred|

|Tipo de respuesta|Función|
|---|---|
|Echo Reply|Responde a ping|
|Destination Unreachable|Indica que el paquete no puede entregarse|
|Redirect|Indica que se use otro router|
|Time Exceeded|El TTL del paquete llegó a 0|
|Parameter Problem|Problema con cabecera del paquete|
|Source Quench|Flujo demasiado rápido, solicita reducir velocidad|

### **TTL (Time-To-Live)**

- Limita la vida de un paquete en la red.
    
- Se decrementa 1 cada vez que pasa por un router.
    
- Cuando TTL = 0, el paquete se descarta y se envía un mensaje ICMP “Time Exceeded”.
    

> Podemos usar TTL para **contar saltos** y estimar la distancia al destino, e incluso **identificar sistemas operativos** según valores típicos:

- Windows: 128
    
- Linux/macOS: 64
    
- Solaris: 255
    

---

## 4️⃣ **Voice Over IP (VoIP) y SIP**

VoIP permite transmitir **voz y multimedia** por Internet en lugar de líneas telefónicas tradicionales.  
Ejemplos: Skype, Zoom, WhatsApp, Slack.

### Protocolos principales

|Protocolo|Puerto|Función|
|---|---|---|
|SIP|5060/5061 TCP|Señalización de llamadas VoIP|
|H.323|1720 TCP|Multimedia sobre redes IP (menos usado que SIP)|

### Métodos SIP más comunes

|Método|Función|
|---|---|
|INVITE|Inicia sesión o invita a un endpoint|
|ACK|Confirma INVITE recibido|
|BYE|Termina una sesión|
|CANCEL|Cancela INVITE pendiente|
|REGISTER|Registra un usuario SIP en el servidor|
|OPTIONS|Consulta capacidades de un servidor/endpoint|

> SIP también puede permitir **enumeración de usuarios**, lo que podría ser un vector de ataque si se explota incorrectamente.
