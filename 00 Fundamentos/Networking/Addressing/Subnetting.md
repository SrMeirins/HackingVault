## **1️⃣ ¿Qué es Subnetting?**

**Subnetting** es el proceso de **dividir un rango de direcciones IPv4 en subredes más pequeñas**.  
Cada subred funciona como una **pequeña red dentro de la red principal**, con su propio rango de direcciones IP, y permite **organizar y gestionar mejor los dispositivos de la red**.

**Analogía:**

- Imagina un gran edificio con muchos departamentos.
    
- Cada departamento tiene su propia puerta de entrada (subred).
    
- Subnetting permite **asignar correctamente cada dispositivo** a su "departamento" y facilitar la comunicación dentro y fuera del mismo.
    

**Beneficios de Subnetting:**

1. **Optimiza el uso de direcciones IP.**
    
2. **Mejora la seguridad**, separando dispositivos en redes lógicas.
    
3. **Facilita la gestión de tráfico**, evitando saturación de la red.
    
4. **Permite escalar redes grandes** sin problemas.
    

---

## **2️⃣ Partes de una dirección IPv4**

Una dirección IPv4 se divide en dos partes:

|Parte|Función|
|---|---|
|**Network (Red)**|Bits fijos según la máscara de subred. Indica la red principal a la que pertenece el host.|
|**Host (Equipo)**|Bits que se pueden cambiar para asignar a dispositivos dentro de la subred.|

**Ejemplo:**

```
IPv4: 192.168.12.160
Subnet Mask: 255.255.255.192
CIDR: /26
```

- `/26` indica que los primeros 26 bits corresponden a la **red**.
    
- Los últimos 6 bits corresponden a los **hosts**.
    

---

## **3️⃣ Direcciones clave en cada subred**

Para cada subred hay **direcciones especiales**:

| Dirección               | Función                                                                                                                    |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Network Address**     | Todos los bits de host en 0. Representa la subred. Ejemplo: 192.168.12.128/26                                              |
| **Broadcast Address**   | Todos los bits de host en 1. Se usa para enviar mensajes a todos los dispositivos de la subred. Ejemplo: 192.168.12.191/26 |
| **First Host**          | Primer IP asignable a un dispositivo. Ejemplo: 192.168.12.129                                                              |
| **Last Host**           | Última IP asignable a un dispositivo. Ejemplo: 192.168.12.190                                                              |
| **Total Hosts Usables** | Número de IPs asignables a dispositivos = Total de IPs - 2 (network + broadcast) → 62 en este ejemplo                      |

> 💡 Siempre recuerda que **network y broadcast no se asignan a hosts**.

---

## **4️⃣ Cómo separar la red y el host (Subnet Mask)**

La **máscara de subred** indica **cuántos bits son de red y cuántos de host**.

- `/26` → 26 bits de red, 6 bits de host.
    
- Cada bit de host puede cambiar para generar distintas IPs dentro de la subred.
    
- Fórmula para calcular **hosts disponibles**:  

		Hosts=2^bits de host−2
    

**Ejemplo:**

- Bits de host = 6 → Hosts = 2^6 - 2 = 64 - 2 = 62
    

---

## **5️⃣ Calcular Network y Broadcast**

**Network Address:** poner **todos los bits de host en 0**.  
**Broadcast Address:** poner **todos los bits de host en 1**.

**Ejemplo con /26:**

```
IPv4: 192.168.12.160
Subnet Mask: 255.255.255.192 (/26)
```

- Bits de host: 6
    
- Network Address = 192.168.12.128
    
- Broadcast Address = 192.168.12.191
    
- Hosts utilizables: 192.168.12.129 → 192.168.12.190
    

---

## **6️⃣ Dividir una subred en subredes más pequeñas**

Supongamos que tenemos una subred `/26` con **64 IPs** y queremos crear **4 subredes más pequeñas**.

### **Paso 1: Determinar cuántos bits extra necesitamos**

- Número de subredes requeridas = 4
    
- Fórmula: (2^n = Número de subredes)
    
- ( 2^2 = 4 → n = 2 ) bits adicionales para subredes
    

### **Paso 2: Ajustar la máscara**

- Original: /26
    
- Nueva máscara: /26 + 2 bits → /28
    
- Hosts por subred: 2^(8-4) = 16 IPs (menos 2 reservadas → 14 hosts)
    

### **Paso 3: Dividir el rango**

|Subred|Network|Primer Host|Último Host|Broadcast|CIDR|
|---|---|---|---|---|---|
|1|192.168.12.128|192.168.12.129|192.168.12.142|192.168.12.143|/28|
|2|192.168.12.144|192.168.12.145|192.168.12.158|192.168.12.159|/28|
|3|192.168.12.160|192.168.12.161|192.168.12.174|192.168.12.175|/28|
|4|192.168.12.176|192.168.12.177|192.168.12.190|192.168.12.191|/28|

> ✅ Ahora tenemos 4 subredes independientes, cada una con 14 hosts utilizables.

---

## **7️⃣ Cómo calcular mentalmente**

Subnetting puede parecer complicado, pero con **reglas simples** se vuelve fácil:

### **Paso 1: Identificar el octeto que cambia**

- Cada octeto tiene 8 bits:
    

```
1º octeto /8 | 2º /16 | 3º /24 | 4º /32
```

- Si tenemos `/25`, solo el **4º octeto** cambia.
    
- Red: 192.168.1.0 → 192.168.1.127, luego 192.168.1.128 → 192.168.1.255
    

### **Paso 2: Calcular tamaño de cada subred**

- Número de IPs por subred = 2^(8 - bits de host del octeto que cambia)
    
- Ejemplo: `/25` → 8º bits - 1 = 7 → 2^7 = 128 IPs → usable 126
    

### **Paso 3: Determinar rangos de IP**

- Primer rango: Network → Broadcast
    
- Segundo rango: Siguiente Network → Broadcast
    
- Repetir hasta usar todas las IPs
    

---

## **8️⃣ Reglas y consejos prácticos**

1. **Siempre restar 2 IPs**: una para network y otra para broadcast.
    
2. **Poder de dos**: las subredes siempre se dividen en 2, 4, 8, 16…
    
3. **CIDR ayuda a simplificar**:
    
    - `/24` → 256 IPs, usable 254
        
    - `/28` → 16 IPs, usable 14
        
4. **Recordar octetos**: facilita determinar qué octeto cambia en el subnetting.
    
5. **Subnetting mental**: dividir 256 por 2 tantas veces como bits de host se tengan.
    

---

## **9️⃣ Resumen visual**

```
IP: 192.168.12.160/26
Network: 192.168.12.128
Broadcast: 192.168.12.191
Hosts Usables: 192.168.12.129 → 192.168.12.190

Subredes /28:
1) 192.168.12.128-143
2) 192.168.12.144-159
3) 192.168.12.160-175
4) 192.168.12.176-191
```

> Cada subred ahora funciona como una red **independiente**, segura y ordenada.
