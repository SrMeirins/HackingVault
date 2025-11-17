En redes, entender **cómo viajan los datos**, qué contiene un **paquete IP**, y cómo funcionan **TCP y UDP** es fundamental para pentesting, sniffing y análisis de tráfico.

---

# 🔌 1. **TCP vs UDP — Conceptos Fundamentales**

## 🔷 **TCP (Transmission Control Protocol)**

**Protocolo orientado a conexión.**  
Piensa en ello como una llamada telefónica: ambos extremos se conectan, hablan, confirman, corrigen errores.

### ✔ Características clave:

- Orientado a conexión (se establece un _three-way handshake_).
    
- Fiable: garantiza entrega y orden de los datos.
    
- Detecta y solicita reenvío de datos perdidos.
    
- Más lento debido a mecanismos de control y corrección.
    

### 📌 Usos típicos:

- HTTP/HTTPS
    
- Email (SMTP, IMAP, POP3)
    
- Transferencias de archivos (FTP)
    
- Servicios donde **no se puede perder ni un byte**
    

---

## 🔶 **UDP (User Datagram Protocol)**

**Protocolo sin conexión**, rápido, pero sin garantías.  
Piensa en ello como enviar mensajes en una botella: llegan… o no.

### ✔ Características clave:

- No orientado a conexión.
    
- No garantiza entrega ni orden.
    
- No reenvía paquetes perdidos.
    
- Mucho más rápido y eficiente.
    

### 📌 Usos típicos:

- Streaming de video/audio
    
- Juegos online
    
- Telefonía IP (VoIP)
    
- DNS
    

---

# 📦 2. **IP Packet — Anatomía del Paquete IP**

Un **IP packet** es como un **sobre con una carta dentro**:

- **El sobre = IP Header** → Instrucciones para el envío.
    
- **La carta = Payload** → Datos reales de transporte (TCP/UDP, ICMP…).
    

---

## 📬 **IP Header — Campos Principales Explicados**

|Campo|Explicación|
|---|---|
|**Version**|Indica si el paquete es IPv4 o IPv6|
|**Header Length**|Tamaño del encabezado IP|
|**Class of Service (TOS/DSCP)**|Prioridad del tráfico|
|**Total Length**|Longitud total del paquete|
|**Identification (IP ID)**|Identifica fragmentos de un mismo paquete|
|**Flags**|Control de fragmentación|
|**Fragment Offset**|Posición del fragmento dentro del paquete original|
|**TTL (Time To Live)**|Máximo de saltos que puede realizar antes de descartarse|
|**Protocol**|Protocolo de capa superior (TCP=6, UDP=17, ICMP=1…)|
|**Checksum**|Verificación de errores del header|
|**Source/Destination IP**|Dirección origen y destino|
|**Options**|Parámetros opcionales (ej. Record-Route)|
|**Padding**|Alineación del header|

---

# 🕵️‍♂️ 3. **Uso del IP ID — Identificar hosts que comparten origen**

El **IP ID** incrementa normalmente de manera secuencial por host.  
Si vemos varios paquetes con IPs distintas pero **IP ID consecutivos**, podemos inferir:

👉 **Corresponden a la misma máquina con múltiples interfaces/IPs.**

### Ejemplo (tcpdump):

```
IP 10.129.1.100 > 10.129.1.1: id 1337  
IP 10.129.1.100 > 10.129.1.1: id 1338  
IP 10.129.2.200 > 10.129.1.1: id 1339  
IP 10.129.2.200 > 10.129.1.1: id 1340  
```

IPs distintas → pero **IP IDs continuos** → mismo host.

---

# 🌍 4. **Record-Route (RR) — Rutas dentro de un paquete IP**

El campo **Record-Route** almacena las direcciones IP de cada router que atraviesa un paquete.

### Ejemplo con ping:

```
ping -c 1 -R <IP>
```

Salida (explicada):

```
RR: 10.10.14.38       (tu máquina)
    10.129.0.1        (router 1)
    10.129.143.158    (destino)
    10.129.143.158    (retorno)
    10.10.14.1        (router 1 de vuelta)
    10.10.14.38       (tu máquina)
```

Esto te da una mini-ruta similar a traceroute.

---

# 🧭 5. **Traceroute — Funcionamiento Interno**

Traceroute descubre cada salto usando **TTL creciente**.

### 🔍 ¿Cómo funciona?

1. Envía un paquete con **TTL = 1** → primer router lo descarta → envía _ICMP Time Exceeded_.
    
2. TTL = 2 → segundo router responde.
    
3. Repite aumentando el TTL hasta llegar al destino.
    
4. Cuando llega:
    
    - TCP SYN/ACK → puerto abierto
        
    - TCP RST → puerto cerrado pero host alcanzado
        

### Diferencias por sistema:

- Linux/macOS: traceroute usa **UDP** por defecto.
    
- Windows: tracert usa **ICMP Echo**.
    

---

# 📨 6. **IP Payload — Los Datos Reales**

El payload puede contener:

- TCP segments
    
- UDP datagrams
    
- ICMP messages
    
- Otros protocolos
    

Es **la parte útil** del paquete.

---

# 📡 7. **TCP Segment — Estructura y Explicación**

Un segmento TCP incluye:

### 🔹 Campos importantes:

- **Source/Destination Port** → Identifican servicios
    
- **Sequence Number** → Orden de bytes enviados
    
- **Acknowledgment Number** → Confirmación de datos recibidos
    
- **Flags** (SYN, ACK, FIN, RST, PSH, URG)
    
- **Window Size** → Control de flujo
    
- **Checksum** → Verificación de errores
    
- **Urgent Pointer** → Datos prioritarios
    

### 🔹 TCP es fiable porque:

✔ reenvía paquetes perdidos  
✔ controla congestión  
✔ garantiza el orden  
✔ establece y cierra conexiones limpiamente

---

# 📩 8. **UDP Datagram — Funcionamiento Simple**

UDP contiene:

- **Source Port**
    
- **Destination Port**
    
- **Length**
    
- **Checksum**
    

Sin ventanas, sin secuencia, sin control.  
Máxima velocidad, mínima sobrecarga.

### Traceroute con UDP:

Cuando llega al destino:  
→ este responde **ICMP Port Unreachable** → traceroute sabe que llegó.

---

# 🎭 9. **Blind Spoofing — Suplantación de IP sin ver respuestas**

Ataque avanzado donde un atacante:

- Manipula el **IP header (IP spoofing)**.
    
- Modifica puertos origen/destino.
    
- Forja un **ISN (Initial Sequence Number)** válido para engañar al receptor.
    

### Riesgos:

- Desincroniza sesiones.
    
- Fuerza desconexiones.
    
- Puede permitir _session hijacking_.
    
- Permite ataques DoS con paquetes falsificados.
    

**El atacante no puede ver las respuestas**, por eso es “blind”.  
Sin embargo, con predicción de secuencia o condiciones predecibles, puede manipular conexiones.

---

# 📘 **Resumen General**

|Tema|Concepto clave|Aplicación|
|---|---|---|
|TCP|Fiable, orientado a conexión|Web, correo, servicios críticos|
|UDP|Rápido, no fiable|Streaming, juegos, VoIP|
|IP Packet|Estructura de enrutamiento|Fundamental en sniffing|
|IP ID|Identificación de fragmentos|Detectar hosts multi-IP|
|Record-Route|Lista de saltos|Análisis de rutas|
|Traceroute|TTL + ICMP/UDP|Mapear redes|
|TCP/UDP payloads|Datos finales|Pentesting, debugging|
|Blind Spoofing|Manipulación sin respuestas|DoS, evasión, pruebas avanzadas|
