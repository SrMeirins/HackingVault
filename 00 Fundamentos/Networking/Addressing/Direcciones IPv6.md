IPv6 es el **sucesor de IPv4**, diseñado para resolver el problema del **agotamiento de direcciones IPv4**. Su longitud es **128 bits**, frente a los 32 bits de IPv4, lo que permite un espacio de direcciones prácticamente ilimitado.

---

# 1️⃣ Comparación IPv4 vs IPv6

|Característica|IPv4|IPv6|
|---|---|---|
|Longitud|32 bits|128 bits|
|Capa OSI|Network Layer|Network Layer|
|Espacio de direcciones|~4.3 mil millones|~340 undecillones|
|Notación|Decimal|Hexadecimal|
|Ejemplo de prefijo|10.10.10.0/24|fe80::dd80:b1a9:6687:2d3b/64|
|Configuración dinámica|DHCP|SLAAC / DHCPv6|
|IPsec|Opcional|Obligatorio|
|Multihoming|Limitado|Varias direcciones por interfaz|
|Tamaño máximo de paquete|65,535 bytes|4 GBytes|

---

# 2️⃣ Ventajas principales de IPv6

- **Mayor espacio de direcciones**: 128 bits frente a 32 bits
    
- **Autoconfiguración de direcciones**: SLAAC (Stateless Address Autoconfiguration)
    
- **Múltiples direcciones por interfaz**
    
- **Enrutamiento más eficiente**
    
- **Seguridad end-to-end** con IPsec obligatorio
    
- **Paquetes de hasta 4 GByte**
    

---

# 3️⃣ Tipos de direcciones IPv6

|Tipo|Descripción|
|---|---|
|**Unicast**|Para una única interfaz.|
|**Anycast**|Para varias interfaces; solo una recibe el paquete.|
|**Multicast**|Para varias interfaces; todas reciben el mismo paquete.|

**Nota:** IPv6 **no tiene broadcast**. En su lugar, usa multicast para descubrimiento y comunicación con múltiples nodos.

---

# 4️⃣ Sistema hexadecimal

IPv6 usa **hexadecimal (hex)** para representar direcciones largas de manera más compacta y legible.

|Decimal|Hex|Binario|
|---|---|---|
|1|1|0001|
|2|2|0010|
|3|3|0011|
|4|4|0100|
|5|5|0101|
|6|6|0110|
|7|7|0111|
|8|8|1000|
|9|9|1001|
|10|A|1010|
|11|B|1011|
|12|C|1100|
|13|D|1101|
|14|E|1110|
|15|F|1111|

### Ejemplo: IPv4 → hexadecimal

IPv4: `192.168.12.160`

|Octeto|Decimal|Binario|Hexadecimal|
|---|---|---|---|
|1|192|11000000|C0|
|2|168|10101000|A8|
|3|12|00001100|0C|
|4|160|10100000|A0|

---

# 5️⃣ Formato de IPv6

IPv6 tiene **128 bits**, divididos en **8 bloques de 16 bits** (4 hexadecimales por bloque). Cada bloque se separa con `:` en lugar de `.` como en IPv4.

### Ejemplo completo:

```
fe80:0000:0000:0000:dd80:b1a9:6687:2d3b/64
```

### Ejemplo abreviado:

- Se omiten **ceros iniciales** en cada bloque.
    
- Se pueden reemplazar **bloques consecutivos de ceros** por `::` (una sola vez).
    

```
fe80::dd80:b1a9:6687:2d3b/64
```

---

# 6️⃣ Partes de una dirección IPv6

IPv6 se divide en **dos partes principales**:

1. **Network Prefix (Prefijo de red)**
    
    - Identifica la red, subred o rango de direcciones.
        
    - Longitud típica: `/64` (puede ser `/32`, `/48`, `/56` según proveedor).
        
2. **Interface Identifier (Identificador de interfaz o Suffix)**
    
    - Corresponde al **host**.
        
    - Generalmente derivado de la **MAC de 48 bits** y extendido a **64 bits**.
        

```
IPv6: fe80::dd80:b1a9:6687:2d3b/64
Prefix: fe80::/64
Interface ID: dd80:b1a9:6687:2d3b
```

---

# 7️⃣ Notación y reglas RFC 5952

RFC 5952 define **la forma recomendada de escribir IPv6**:

1. Todas las letras en **minúscula**
    
2. **Se eliminan ceros iniciales** en cada bloque
    
3. **Bloques consecutivos de ceros** se reemplazan por `::`
    
4. **Solo una vez** se permite usar `::` en la dirección
    

### Ejemplo:

```
Original: fe80:0000:0000:0000:dd80:b1a9:6687:2d3b/64
Reducida: fe80::dd80:b1a9:6687:2d3b/64
```

---

# 8️⃣ Fórmulas y cálculos importantes

- **Número de direcciones en un prefijo:**
    

```markdown
Número de direcciones = 2^(128 - longitud_prefijo)
```

- **Ejemplo con /64:**
    

```markdown
Direcciones disponibles = 2^(128-64) = 2^64
```

- **Conversión IPv4 → hexadecimal para IPv6 embedding**:
    

```markdown
IPv4 192.168.12.160 → C0.A8.0C.A0
```

- **Formato de Interface ID a partir de MAC**:
    

```markdown
MAC 48 bits → IPv6 Interface ID 64 bits
Se inserta FF:FE en medio:
MAC: DE:AD:BE:EF:13:37
IPv6 Interface ID: DE:AD:BE:FF:FE:EF:13:37
```

---

# 9️⃣ Resumen práctico

- IPv6: **128 bits**, hex, 8 bloques de 16 bits
    
- Eliminación de **broadcast**, uso de multicast
    
- Tipos de direcciones: **Unicast, Anycast, Multicast**
    
- Prefijo `/64` por defecto; Interface ID 64 bits
    
- Notación corta y legible gracias a `::` y eliminación de ceros iniciales
    
- Ventajas: espacio de direcciones gigante, autoconfiguración, seguridad end-to-end, mejor enrutamiento
