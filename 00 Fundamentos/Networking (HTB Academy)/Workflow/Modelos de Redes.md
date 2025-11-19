Cuando dos dispositivos se comunican (tu PC y un servidor, por ejemplo), los datos **pasan por capas**, cada una con su función. Estas capas forman modelos de referencia:

- **OSI → 7 capas**
    
- **TCP/IP → 4 capas**
    

Ambos modelos describen **cómo viajan los datos por la red**, desde que una aplicación los genera hasta que llegan al dispositivo destino.

---

# 1️⃣ OSI vs TCP/IP (Resumen rápido)

|Modelo|Capas|Para qué se usa|
|---|---|---|
|**OSI (7 capas)**|Aplicación, Presentación, Sesión, Transporte, Red, Enlace, Física|Modelo teórico → explica _cómo_ funcionan las comunicaciones paso a paso. Muy útil para análisis profundo.|
|**TCP/IP (4 capas)**|Aplicación, Transporte, Internet, Link|Modelo real usado por Internet → describe _cómo funciona la red de verdad_.|

💡 **Piensa así**:

- **TCP/IP** = “cómo funciona realmente Internet”.
    
- **OSI** = “cómo entendemos y estudiamos lo que pasa en cada paso”.
    

---

# 2️⃣ El Modelo OSI (7 capas)

Es un **modelo teórico** que divide la comunicación en 7 bloques bien definidos. Se usa para **entender** qué ocurre en cada fase.

De arriba (más cerca del usuario) a abajo (más cerca del cable):

1. **Aplicación:** Interactúa con el usuario (HTTP, FTP, DNS…)
    
2. **Presentación:** Convierte formatos (cifrado, compresión, codificación)
    
3. **Sesión:** Abre, mantiene y cierra sesiones de comunicación
    
4. **Transporte:** Segmenta datos y garantiza entrega (TCP/UDP)
    
5. **Red:** Direccionamiento y enrutamiento (IP)
    
6. **Enlace:** Transmisión en la red local (MAC, ARP)
    
7. **Física:** Datos “crudos” en forma de bits por cable, fibra, aire…
    

---

# 3️⃣ El Modelo TCP/IP (4 capas)

Mucho más simple. Fusiona varias capas del OSI:

1. **Aplicación**  
    (Incluye Aplicación + Presentación + Sesión del OSI)
    
2. **Transporte**  
    → TCP (fiable) / UDP (rápido)
    
3. **Internet**  
    → IP, ICMP, ARP, enrutamiento
    
4. **Link (Acceso a Red)**  
    → Ethernet, WiFi, VLANs, MAC
    

💬 **El TCP/IP es práctico y real**: el Internet moderno funciona así.

---

# 4️⃣ ¿Cuál es la diferencia real?

- **TCP/IP es un conjunto de protocolos reales** (TCP, IP, UDP, ICMP...).
    
- **OSI es un modelo teórico** usado para explicar conceptos.
    

**TCP/IP es flexible**: solo exige cumplir reglas generales.  
**OSI es estricto**: define capas y funciones muy claramente.

Por eso, en la práctica todo el mundo usa **TCP/IP**, pero para estudiar, diagnosticar o hacer pentesting, el **modelo OSI** da precisión.

---

# 5️⃣ Encapsulación: Cómo viaja un paquete (explicado simple)

Cuando envías datos (por ejemplo, una página web), los datos **bajan capa por capa**.

En cada capa:

1. Se añade un **encabezado (header)** con información útil.
    
2. El conjunto se convierte en la **PDU** correspondiente.
    

👉 **PDU** = cómo se llama el paquete en cada capa.

| Capa OSI                           | PDU                                      |
| ---------------------------------- | ---------------------------------------- |
| Aplicación / Presentación / Sesión | **Datos**                                |
| Transporte                         | **Segmento (TCP)** / **Datagrama (UDP)** |
| Red                                | **Paquete**                              |
| Enlace                             | **Trama (Frame)**                        |
| Física                             | **Bits**                                 |

Ejemplo real (HTTP):

```
Aplicación → Datos
Transporte → Segmento TCP
Red → Paquete IP
Enlace → Trama Ethernet
Física → Bits por el cable
```

🥡 **Envío = encapsular**  
🥡 **Recepción = desencapsular**

---

# 6️⃣ ¿Por qué esto importa en Pentesting?

Porque para analizar tráfico, romper protocolos, sniffear o manipular paquetes necesitas saber:

- Qué ocurre en cada capa
    
- Qué protocolos intervienen
    
- Qué datos puedes interceptar/modificar
    
- Cómo viajan realmente los paquetes por la red
    

➡️ **TCP/IP** te da una visión global del funcionamiento  
➡️ **OSI** te permite diseccionar cada etapa con lupa

En análisis de tráfico (PCAP, Wireshark) usamos ambos mentalmente:

- “¿Esto es capa 2 o capa 3?”
    
- “¿Este paquete está fragmentado en Capa 4?”
    
- “¿Es un problema de transporte o aplicación?”
    

---

# 🎓 Resumen Ultrarrápido

- **OSI (7 capas):** Modelo teórico → perfecto para aprender
    
- **TCP/IP (4 capas):** Modelo real → así funciona Internet
    
- **Encapsulación:** cada capa añade su propio header
    
- **Pentesting:** OSI = disección profunda, TCP/IP = visión global real
