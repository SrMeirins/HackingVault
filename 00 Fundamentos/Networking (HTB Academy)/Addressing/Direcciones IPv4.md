## **1️⃣ Concepto básico**

Cada dispositivo en una red necesita **una dirección única** para comunicarse. Esto se hace a dos niveles:

1. **MAC Address**
    
    - Identifica un dispositivo **dentro de la misma red local (LAN)**.
        
    - Es un identificador físico grabado en la tarjeta de red.
        
    - Es como el número de apartamento dentro de un edificio.
        
2. **IP Address (IPv4/IPv6)**
    
    - Permite localizar un dispositivo **en cualquier red**, incluso a través de Internet.
        
    - Compuesta por **parte de red** + **parte de host**.
        
    - La dirección postal completa del edificio donde vive el apartamento.
        

> 🔑 Importante: Conocer solo la MAC no permite enviar datos a otra red; para eso necesitamos la IP.

---

## **2️⃣ IPv4: Estructura y notación**

- IPv4 es la versión más usada de IP.
    
- **32 bits**, organizados en **4 octetos** (8 bits cada uno).
    
- Cada octeto se representa en **decimal** (0–255) y se separa por puntos:
    

**Ejemplo:**

```
IPv4: 192.168.10.39
Binario: 11000000.10101000.00001010.00100111
```

- **Parte de red:** identifica la red a la que pertenece el host
    
- **Parte de host:** identifica el dispositivo dentro de la red
    

---

## **3️⃣ Clases de IPv4 (histórico)**

Antes del uso de CIDR, las IP se dividían en clases:

|Clase|Red inicial|Rango de hosts|Subnet Mask|CIDR|
|---|---|---|---|---|
|A|1.0.0.0|16,777,214|255.0.0.0|/8|
|B|128.0.0.0|65,534|255.255.0.0|/16|
|C|192.0.0.0|254|255.255.255.0|/24|
|D|224.0.0.0|Multicast|–|–|
|E|240.0.0.0|Reservado|–|–|

> Hoy en día se usa **CIDR** para flexibilidad, en lugar de clases fijas.

---

## **4️⃣ Subnetting y Gateway**

- **Subnetting:** dividir la red en subredes más pequeñas usando **subnet masks**.
    
- **Subnet Mask:** indica qué parte de la IP es red y cuál host.
    

**Ejemplo: Red 192.168.10.0/24**

```
Network Address: 192.168.10.0   → identifica la red
First Host:      192.168.10.1   → primer host asignable
Last Host:       192.168.10.254 → último host asignable
Broadcast:       192.168.10.255 → mensaje a todos los dispositivos
Gateway:         192.168.10.1   → router que conecta la red a otras redes
```

- **Default Gateway**: IP del router que permite que los dispositivos de la red se comuniquen con otras redes o Internet.
    

> 🔑 Regla práctica: El gateway suele ser la **primera IP disponible** de la subred.

---

## **5️⃣ Representación binaria de IPv4**

Cada octeto = 8 bits, cada bit tiene un valor específico:

```
Valores: 128 64 32 16 8 4 2 1
```

**Ejemplo IP: 192.168.10.39**

|Octeto|Binario|Decimal|
|---|---|---|
|1|11000000|192|
|2|10101000|168|
|3|00001010|10|
|4|00100111|39|

- La conversión **binario → decimal** se hace sumando los valores de los bits que están en 1.
    

**Subnet mask ejemplo:** 255.255.255.0

```
Binario: 11111111.11111111.11111111.00000000
CIDR: /24 → los primeros 24 bits representan la red
```

---

## **6️⃣ CIDR (Classless Inter-Domain Routing)**

- Reemplaza la limitación de las clases A/B/C y permite **subredes de cualquier tamaño**.
    
- Se indica como `IP/Prefijo`, donde el prefijo es el número de bits que pertenecen a la red.
    

**Ejemplo:**

```
IP: 192.168.10.39
Subnet mask: 255.255.255.0
CIDR: 192.168.10.39/24
```

> 🔑 /24 → los primeros 24 bits son red, los últimos 8 bits son hosts.  
> Esto permite 2⁸-2 = 254 hosts por subred.

---

## **7️⃣ Funciones principales de las IP**

1. **Identificación:** cada dispositivo debe ser único en la red.
    
2. **Direccionamiento:** permite enviar datos al dispositivo correcto.
    
3. **Ruteo:** ayuda a los routers a mover los paquetes de una red a otra.
    
4. **Broadcast:** comunicación a todos los dispositivos de la red.
    
5. **Gateway:** conexión entre redes diferentes.
    

---

## **8️⃣ Resumen visual**

```
Dispositivo A → IP: 192.168.10.10 → Gateway 192.168.10.1 → Internet → IP destino
IP = dirección postal
MAC = apartamento exacto
Subnet = barrio (división de red)
Broadcast = anunciar a todos los vecinos
CIDR = tamaño del barrio
```