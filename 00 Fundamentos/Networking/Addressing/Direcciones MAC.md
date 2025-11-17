
Las **MAC Addresses** (Media Access Control Addresses) son direcciones únicas que identifican **físicamente** a cada dispositivo en una red local. Funcionan en la **Capa 2 del modelo OSI (Data Link Layer)**.

---

# 1️⃣ ¿Qué es una MAC Address?

- Es una **dirección única de 48 bits** (6 bytes)
    
- Identifica a la **tarjeta de red**: Ethernet, Wi-Fi, Bluetooth, etc.
    
- Es asignada por el **fabricante**, pero **puede modificarse** (MAC Spoofing)
    
- Se escribe en **hexadecimal** y en bloques de 6 pares:
    

Ejemplos válidos:

```
DE:AD:BE:EF:13:37
DE-AD-BE-EF-13-37
DEAD.BEEF.1337
```

---

# 2️⃣ Estructura de una MAC Address

Una MAC Address está dividida en **dos partes**:

|Parte|Tamaño|Significado|
|---|---|---|
|**OUI (Organizationally Unique Identifier)**|24 bits (3 bytes)|Identifica al fabricante|
|**NIC (Network Interface Controller)**|24 bits (3 bytes)|Identificador único asignado por el fabricante|

### Ejemplo desglosado

MAC: `DE:AD:BE:EF:13:37`

|Octeto|Hex|Binario|
|---|---|---|
|1|DE|1101 1110|
|2|AD|1010 1101|
|3|BE|1011 1110|
|4|EF|1110 1111|
|5|13|0001 0011|
|6|37|0011 0111|

La MAC completa es:

```
OUI → DE:AD:BE
NIC → EF:13:37
```

---

# 3️⃣ ¿Para qué sirve la MAC Address?

Cuando se envían datos por red, el paquete debe saber a **qué dispositivo físico** enviarse.  
Para eso, se usa la MAC en la Capa 2.

📌 **Importante:**

- Si el destino está en la misma subred → se usa su **MAC real**
    
- Si está en otra subred → se envía a la **MAC del router (Default Gateway)**
    

📌 La traducción de **IP → MAC** se hace usando el protocolo **ARP** (explicado más abajo).

---

# 4️⃣ Tipos especiales de MAC Addresses

La MAC address tiene bits especiales que determinan su propósito.  
Estos bits están en el **primer octeto**.

## ✔️ 4.1 Unicast (último bit = 0)

Significa que el paquete va **solo a 1 dispositivo**.

Ejemplo:

```
DE:AD:BE:EF:13:37
```

Binario del primer octeto:

```
1101 1110 → último bit = 0 → unicast
```

## ✔️ 4.2 Multicast (último bit = 1)

El paquete se envía a **muchos dispositivos**, pero no a todos.

Ejemplo:

```
01:00:5E:EF:13:37
```

Primer octeto binario:

```
0000 0001 → último bit = 1 → multicast
```

## ✔️ 4.3 Broadcast

Va a **todos los dispositivos de la red local**.

```
FF:FF:FF:FF:FF:FF
```

Binario:

```
1111 1111 1111 1111 ...
```

---

# 5️⃣ Dirección global vs. local

En el **segundo bit menos significativo** del primer octeto:

|Bit|Tipo|Significado|
|---|---|---|
|0|**Global**|Asignada por IEEE a fabricantes|
|1|**Local**|Administrada por software (por ej. MAC spoofing)|

Ejemplo de Local:

```
02:xx:xx:xx:xx:xx
```

Rango local común:

```
02:00:00:00:00:00
06:00:00:00:00:00
0A:00:00:00:00:00
0E:00:00:00:00:00
```

---

# 6️⃣ 📜 Proceso ARP (Address Resolution Protocol)

El **ARP** convierte una dirección **IP (Capa 3)** en una **MAC Address (Capa 2)**.

Es usado en redes IPv4 para descubrir "¿Qué MAC tiene esta IP?"

### 📌 Funcionamiento paso a paso

### **1. ARP Request (Broadcast)**

Se envía a TODOS los equipos:

```
Who has 10.129.12.101? Tell 10.129.12.100
```

### **2. ARP Reply (Unicast)**

Solo contesta el dueño de la IP:

```
10.129.12.101 is at AA:AA:AA:AA:AA:AA
```

### Ejemplo real (tshark):

```
1  10.129.12.100 -> 10.129.12.255  ARP  Who has 10.129.12.101?
2  10.129.12.101 -> 10.129.12.100  ARP  10.129.12.101 is at AA:AA:AA:AA:AA:AA
```

---

# 7️⃣ Ataques basados en MAC Address

Las MAC no son un mecanismo de seguridad.  
Son muy fáciles de **suplantar**, manipular o saturar.

### ✔️ 1. MAC Spoofing

Cambiar la MAC para hacerse pasar por otro dispositivo.

Usado para:

- saltar filtrado por MAC
    
- ocultar identidad
    
- ataques MITM
    

### ✔️ 2. MAC Flooding

Se envían miles de MAC falsas a un switch.

Resultado:

- El switch se queda sin espacio en su tabla MAC
    
- Empieza a comportarse como un hub
    
- **Filtra tráfico a todas las interfaces → MITM posible**
    

### ✔️ 3. Abusar de MAC Filtering

Si una red solo permite ciertas MAC:

- Podemos **imitar** una MAC permitida (spoofing)
    
- Ganar acceso a la red
    

---

# 8️⃣ **ARP Spoofing / ARP Poisoning**

Es uno de los ataques MITM más comunes en redes locales.

📌 El atacante envía respuestas ARP falsas, diciendo:

> "El gateway soy yo"

Esto hace que la víctima envíe todo su tráfico al atacante.

### Ejemplo real:

```
1  Attacker -> Victim   ARP  10.129.12.255 is at CC:CC:CC:CC:CC:CC
2  Victim   -> Broadcast ARP Who has 10.129.12.100?
3  Attacker -> Victim   ARP 10.129.12.100 is at CC:CC:CC:CC:CC:CC
4  Victim   -> Gateway? ARP Who has 10.129.12.255?
```

El atacante consigue:

- Sniffing
    
- MITM
    
- Robo de cookies
    
- Modificación de tráfico
    

---

# 9️⃣ Cómo protegerse

- **Static ARP entries** (no escalable)
    
- **DHCP Snooping**
    
- **Dynamic ARP Inspection (DAI)**
    
- **IPS/IDS**
    
- **Seguridad en Switches (Port Security)**
    
- Usar **HTTPS**, **SSH**, **IPSec**, etc.
