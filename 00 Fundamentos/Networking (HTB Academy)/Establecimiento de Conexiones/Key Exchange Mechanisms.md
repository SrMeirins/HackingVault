Los **mecanismos de intercambio de claves** permiten que dos partes que NO se conocen previamente puedan acordar una clave secreta para comunicarse de forma segura **aun estando en un canal inseguro** (como Internet).

Estos métodos son esenciales porque:

- Sin una clave secreta, no se puede cifrar el tráfico.
    
- Sin un intercambio seguro, un atacante podría interceptar la clave.
    
- Son la base de protocolos como **TLS, VPNs, SSH, IPsec, HTTPS**, etc.
    

Todas estas técnicas permiten:  
✔ Crear un **secreto compartido**  
✔ Sobre un canal **no confiable**  
✔ Sin enviar nunca la clave **directamente**

---

# 🟦 **1. ¿Cómo funcionan los intercambios de claves?**

La idea general:

1. Cada parte tiene información **pública** (que se puede enviar por Internet sin problemas).
    
2. Cada parte genera información **privada** (que no comparte).
    
3. Usan matemáticas que permiten calcular un **secreto común**,  
    pero que ES IMPOSIBLE reconstruir sólo con la parte pública.
    

🔐 **Metáfora sencilla:**  
Como si dos personas mezclaran ingredientes secretos con ingredientes públicos para obtener un color final. Desde fuera solo ves los ingredientes públicos, pero no puedes deducir el color que obtienen juntas.

---

# 🟦 **2. Diffie–Hellman (DH)**

### 🧠 **Qué es**

Es el método clásico para que dos partes acuerden una clave secreta **sin haberse visto antes** y sin compartir contraseñas previas.

Es la base conceptual de muchas tecnologías modernas:

- TLS
    
- SSH
    
- IPsec
    
- VPNs
    

### ▶ ¿Cómo funciona?

Cada parte genera:

- Un número público
    
- Un número privado
    

Intercambian solo los **públicos**, pero usando matemáticas modulares obtienen la MISMA clave secreta final.

### 🟥 Vulnerabilidad: MITM

Diffie-Hellman **no autentica** a las partes.  
Si no añades autenticación:

- Un atacante puede ponerse en medio,
    
- Hacer dos intercambios DH independientes,
    
- Y leer/modificar todo sin que lo detectes.
    

Por eso en los protocolos **siempre se acompaña** de certificados o firmas digitales.

### 🟩 Ventajas:

- Simple y elegante.
    
- No requiere compartir secretos antes.
    

### 🟥 Desventajas:

- Sin autenticación → vulnerable a MITM.
    
- Las operaciones matemáticas pueden ser pesadas (más lento que ECC).
    

---

# 🟦 **3. RSA (Rivest–Shamir–Adleman)**

### 🧠 ¿Qué es?

Un algoritmo asimétrico basado en:

- Multiplicar números primos → fácil
    
- Factorizar números enormes → muy difícil
    

### ▶ ¿Cómo se usa RSA para intercambio de claves?

No se usa para firmar directamente claves grandes.  
Lo habitual es:

1. Se genera una **clave simétrica** aleatoria.
    
2. Se cifra la clave con la **clave pública RSA del servidor**.
    
3. El servidor la descifra con su clave privada.
    

Resultado: ambas partes ya comparten la clave secreta simétrica.

### 📌 Usos habituales:

- TLS/HTTPS (especialmente antes de ECDHE).
    
- Firmar y verificar firmas digitales.
    
- Autenticación inicial en protocolos.
    
- Protección de datos sensibles.
    

### 🟥 Desventajas:

- Mucho más lento que ECDH.
    
- Requiere claves muy grandes (2048–4096 bits).
    

### 🟩 Ventajas:

- Muy extendido.
    
- Robusto si la clave es suficientemente grande.
    

---

# 🟦 **4. ECDH — Elliptic Curve Diffie-Hellman**

### 🧠 Qué es

Es una versión moderna de Diffie-Hellman usando **criptografía de curva elíptica (ECC)**.

ECC permite:

- Mismas garantías de seguridad…
    
- …pero con claves muchísimo más pequeñas.
    
- …y con un rendimiento MUCHO mayor.
    

Por eso se usa en:

- TLS moderno (ECDHE)
    
- VPNs (IKEv2)
    
- SSH
    
- Protocolos móviles
    
- Dispositivos de baja potencia (IoT)
    

### ⭐ Ventajas importantes:

✔ Más rápido  
✔ Más seguro a igualdad de tamaño  
✔ Menos consumo de CPU  
✔ Proporciona **Perfect Forward Secrecy** (PFS)

---

# 🟦 **5. ECDSA — Firmas digitales con curvas elípticas**

ECDSA no es un intercambio de claves, sino un **algoritmo de firmas** que se usa para autenticar las partes.

Es importante porque:

- Diffie-Hellman por sí solo NO autentica.
    
- Con ECDSA se pueden **firmar** los mensajes DH para evitar MITM.
    

Aplicaciones:

- Certificados en TLS
    
- Firmas de software
    
- Autenticación en IKE/IPsec
    
- Blockchain (Bitcoin usa ECDSA)
    

---

# 🟦 **6. Comparativa rápida de algoritmos**

|Algoritmo|Acrónimo|Seguridad y características|
|---|---|---|
|Diffie-Hellman|DH|Seguro si hay autenticación, pero más lento que ECC|
|RSA|RSA|Seguro con claves grandes; pesado computacionalmente|
|Elliptic Curve Diffie-Hellman|ECDH|Rápido, moderno y seguro; estándar actual|
|Elliptic Curve Digital Signature Algorithm|ECDSA|Firmas rápidas y seguras; complementa ECDH|

---

# 🟦 **7. IKE — Internet Key Exchange (clave en VPNs)**

IKE es el protocolo que permite:

- Negociar parámetros de seguridad,
    
- Intercambiar claves,
    
- Autenticar las partes,
    
- Establecer un túnel seguro.
    

Usado en:

- IPsec
    
- VPNs empresariales
    
- Conexiones site-to-site
    

IKE combina:

- DH/ECDH → para obtener un secreto
    
- RSA/ECDSA → para autenticación
    
- AES u otros → para cifrado de datos
    

---

# 🟨 IKE: Modos de operación

## 🔵 Main Mode (modo principal)

- Más seguro.
    
- Protege la identidad.
    
- 6 mensajes.
    
- Más lento.
    

Ideal para:

- Entornos empresariales.
    
- Redes donde la privacidad de la identidad es importante.
    

## 🔵 Aggressive Mode (modo agresivo)

- Mucho más rápido.
    
- SOLO 3 mensajes.
    
- **No protege la identidad** → menos seguro.
    

Se usa cuando:

- Hay restricciones de tiempo.
    
- Los dispositivos son muy limitados.
    

---

# 🟦 **8. Pre-Shared Keys (PSK) en IKE**

Un **PSK** es una contraseña compartida previamente por ambas partes.

### ✔ Ventajas:

- Fácil de implementar.
    
- No necesitas certificados.
    
- Ideal para enlaces pequeños o laboratorio.
    

### ✖ Desventajas:

- Si alguien descubre el PSK → se compromete toda la VPN.
    
- Malas prácticas típicas:
    
    - PSK débiles
        
    - PSK reutilizados
        
    - PSK enviados por correo
        

Los PSK deben intercambiarse por canales seguros (USB, presencia física, canal cifrado alternativo, etc.).

---

# 🟩 **Resumen mental para recordar fácilmente**

|Tecnología|Para qué sirve|Característica clave|
|---|---|---|
|**DH**|Crear secreto compartido|Vulnerable a MITM sin firmas|
|**RSA**|Encriptar clave o firmar|Seguro pero pesado|
|**ECDH**|Intercambio moderno|Rápido + PFS|
|**ECDSA**|Firmar/autenticar|Base de TLS/IPsec moderno|
|**IKE**|Negociar parámetros y claves|Usado en VPNs|
