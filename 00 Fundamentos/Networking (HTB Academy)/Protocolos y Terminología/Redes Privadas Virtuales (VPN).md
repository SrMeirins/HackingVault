Una **Virtual Private Network (VPN)** es una tecnología que permite crear una **conexión segura, cifrada y privada** entre un dispositivo remoto y una red interna (empresa, centro de datos, oficina, etc.). Su propósito principal es que un usuario fuera de la red pueda acceder a recursos internos **como si estuviera físicamente dentro**.

---

# ⭐ 1. Concepto de VPN

Una VPN crea un **túnel cifrado** a través de Internet entre:

- un **cliente VPN** (empleado, administrador, portátil corporativo…),  
    y
    
- un **servidor VPN** dentro de la red privada.
    

Ese túnel:

- protege los datos frente a escuchas,
    
- permite el acceso a recursos internos,
    
- asigna al usuario una **IP interna**, integrándolo en la red privada.
    

---

# ⭐ 2. ¿Para qué se utiliza una VPN?

### 🎯 **Usos principales:**

- Administradores gestionan servidores internos desde cualquier lugar.
    
- Empleados acceden a correo, archivos, intranet o aplicaciones internas.
    
- Conectar sedes remotas mediante un solo “gran” túnel seguro.
    
- Evitar necesidad de líneas privadas dedicadas (mucho más caras).
    

### 🎯 **Ventajas clave:**

- ✔️ **Cifrado** → datos protegidos frente a atacantes y sniffing.
    
- ✔️ **Acceso remoto** → desde casa, hoteles, móvil, etc.
    
- ✔️ **Ahorro de costes** → usa Internet, no líneas privadas.
    
- ✔️ **Integración con la red interna** → el usuario recibe una **IP local**.
    

---

# ⭐ 3. ¿Cómo funciona una VPN? (Explicación clara)

1. El usuario abre el **cliente VPN**.
    
2. El cliente contacta al **servidor VPN** usando Internet.
    
3. Se realiza un proceso de **autenticación** (contraseña, certificado, MFA…).
    
4. Se genera un **túnel cifrado** (IPsec, OpenVPN, WireGuard, etc.).
    
5. El usuario recibe una **IP interna**.
    
6. Todo el tráfico hacia la red corporativa viaja por el túnel cifrado.
    

> Este túnel impide que un atacante entre el cliente y el servidor pueda leer o modificar el tráfico.

---

# ⭐ 4. Componentes esenciales de una VPN

|Elemento|Descripción|
|---|---|
|**Cliente VPN**|Software que se instala en el dispositivo remoto (OpenVPN, IKEv2, WireGuard…). Se encarga de crear y mantener el túnel.|
|**Servidor VPN**|Acepta conexiones, autentica usuarios y enruta el tráfico hacia la red interna. Puede estar en un firewall, router o servidor dedicado.|
|**Cifrado**|Protege los datos mediante algoritmos como **AES**, **ChaCha20**, **IPsec ESP**, etc.|
|**Autenticación**|Métodos como contraseñas, certificados, claves precompartidas (PSK) o MFA. Asegura que solo usuarios autorizados acceden.|

---

# ⭐ 5. Puertos y protocolos usados habitualmente

|Tecnología|Protocolos / Puertos|Uso|
|---|---|---|
|**PPTP**|TCP/1723|Obsoleto, inseguro.|
|**IPsec / IKEv1 / IKEv2**|UDP/500 (IKE), UDP/4500 (NAT-T), Protocolo ESP (50)|VPN muy común en empresas.|
|**ESP (IPsec)**|Protocolo 50|Cifrado del tráfico.|

> IPsec suele aprovechar ESP para cifrar y AH para autenticar, aunque ESP ya puede incluir autenticación opcional.

---

# ⭐ 6. IPsec – Explicación completa

**IPsec (Internet Protocol Security)** es un conjunto de protocolos que cifra y autentica tráfico IP. Muy usado en VPN corporativas y entre sedes.

### 🔐 IPsec proporciona:

- **Confidencialidad** (cifrado del tráfico)
    
- **Integridad** (verificar que no ha sido alterado)
    
- **Autenticación** (verificar origen del paquete)
    

### 🔧 Protocolos principales:

#### 1. **AH (Authentication Header)**

- Aporta **integridad** y **autenticidad**.
    
- No cifra datos → no ofrece confidencialidad.
    
- Verifica que el paquete no ha sido manipulado.
    

#### 2. **ESP (Encapsulating Security Payload)**

- Proporciona **cifrado** y opcionalmente autenticación.
    
- Es el más usado hoy en día para VPN.
    

---

## 🔄 Modos de uso en IPsec

|Modo|Explicación|Uso típico|
|---|---|---|
|**Transport Mode**|Cifra solo la carga útil del paquete IP, no la cabecera.|Comunicación host a host (menos común).|
|**Tunnel Mode**|Cifra **todo** el paquete IP (cabecera + datos).|VPN entre redes o entre cliente ↔ servidor.|

---

# ⭐ 7. Requisitos de firewall para que IPsec funcione

Si un firewall se encuentra entre cliente y servidor, debe permitir:

|Protocolo|Puerto|Función|
|---|---|---|
|**IKE (Internet Key Exchange)**|UDP/500|Negociación de claves y parámetros de seguridad.|
|**IPsec ESP**|Protocolo 50|Transporte cifrado del tráfico VPN.|
|**NAT-T (Encapsulación ESP en UDP)**|UDP/4500|Necesario cuando hay NAT entre cliente y servidor (muy frecuente).|

---

# ⭐ 8. PPTP – Qué es y por qué NO debe usarse

**PPTP (Point-to-Point Tunneling Protocol)** fue una de las primeras tecnologías VPN ampliamente utilizadas.

### ✔️ Ventajas (históricas):

- Fácil de configurar.
    
- Compatibilidad con muchos sistemas.
    

### ❌ Inconvenientes:

- Utiliza **MSCHAPv2**, que depende de **DES**, un cifrado totalmente roto.
    
- Puede romperse con hardware moderno en minutos.
    
- Vulnerable a ataques de fuerza bruta y MITM.
    

👉 **PPTP está considerado inseguro desde 2012** y no se usa en entornos profesionales modernos.

Alternativas actuales:

- **IPsec/IKEv2**
    
- **OpenVPN**
    
- **WireGuard** (rápida, moderna y muy segura)
    
- **L2TP/IPsec**
    

---

# 🧠 Resumen visual final

- Una VPN crea un túnel cifrado entre un dispositivo remoto y una red privada.
    
- Proporciona **seguridad**, **acceso remoto** y **ahorro de costes**.
    
- IPsec es el estándar más robusto → usa AH y ESP.
    
- PPTP está obsoleto y es inseguro.
    
- Requiere cliente, servidor, cifrado y autenticación.
    