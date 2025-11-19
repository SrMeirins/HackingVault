La criptografía es el conjunto de técnicas que permiten **proteger información** durante su transmisión o almacenamiento. Busca garantizar:

- **Confidencialidad** → que solo quien debe pueda leer la información
    
- **Integridad** → que los datos no hayan sido modificados
    
- **Autenticidad** → saber quién envía los datos
    
- **No repudio** → que alguien no pueda negar haber enviado algo
    

Para lograr esto, se usan **algoritmos matemáticos** que transforman los datos en algo ilegible si no tienes la “llave”.

---

# 🔐 1. **Tipos de criptografía**

## **1.1. Criptografía Simétrica**

🔹 Usa **la misma clave** para cifrar y descifrar.  
🔹 Es **muy rápida** → ideal para grandes volúmenes de datos.  
🔹 Principal desventaja: **¿cómo compartes la clave de forma segura?**

### ➤ Ejemplos

- **AES (Advanced Encryption Standard)** → _el estándar actual, muy seguro_
    
- **DES / 3DES** → Algoritmos antiguos, hoy considerados inseguros
    

### ➤ Usos típicos:

- Cifrar discos (BitLocker, LUKS)
    
- VPNs
    
- HTTPS (pero solo después del handshake)
    

---

## **1.2. Criptografía Asimétrica**

🔹 Usa **dos claves diferentes pero matemáticamente relacionadas**:

- **Clave pública** → para cifrar
    
- **Clave privada** → para descifrar
    

🔹 Permite comunicarse de forma segura sin compartir previamente una clave.  
🔹 Es más lenta que la simétrica, pero soluciona el problema del intercambio de claves.

### ➤ Ejemplos:

- **RSA**
    
- **PGP**
    
- **ECC (Elliptic Curve Cryptography)** → más moderna y eficiente
    

### ➤ Usos:

- Certificados web y HTTPS (TLS)
    
- VPNs
    
- Correo cifrado (PGP)
    
- SSH
    
- Firmas digitales
    
- Infraestructuras de Clave Pública (PKI)
    

### **Ventajas clave**

✔ Soluciona el problema de intercambiar claves  
✔ Permite firmar digitalmente  
✔ Seguridad basada en problemas matemáticos muy difíciles

---

# 🔑 2. **Algoritmos importantes**

## **2.1. DES**

- Cifrado por bloques simétrico
    
- Longitud real de clave: **56 bits** (8 bits son checksum)
    
- Obsoleto: puede ser roto hoy con hardware moderno
    

### **3DES**

- Aplica DES **tres veces**
    
- Mucho más seguro que DES
    
- Aun así, considerado viejo comparado con AES
    

---

## **2.2. AES (EL estándar moderno)**

- Cifrado simétrico por bloques
    
- Tamaños de clave: **128, 192 y 256 bits**
    
- Muy rápido y muy seguro
    
- Implementado en hardware en la mayoría de CPUs modernas
    

### **Usos donde aparece AES:**

- WPA2/WPA3 (Wifi)
    
- VPNs (IPsec)
    
- SSH
    
- TLS (HTTPS)
    
- PGP
    
- OpenSSL
    

---

# 🔄 3. **Cipher Modes (Modos de Operación)**

Los algoritmos como AES cifran bloques fijos de datos.  
Los “cipher modes” indican **cómo combinar esos bloques** para cifrar mensajes largos.

### 🧩 Tabla de modos:

|Modo|Descripción|Uso recomendado|
|---|---|---|
|**ECB**|Cifra cada bloque de forma aislada → _inseguro, revela patrones_|NO usar|
|**CBC**|Cada bloque depende del anterior → oculta patrones|Discos, emails, TLS|
|**CFB**|Convierte bloque a flujo de bytes|Streaming, tráfico en tiempo real|
|**OFB**|Parecido a CFB pero mejor generación de flujo|Comunicación en tiempo real|
|**CTR**|Convierte AES en un cifrador en flujo rápido|IPsec, BitLocker, tráfico en red|
|**GCM**|CTR + Integridad (autenticación)|VPNs, TLS moderno, WiFi seguro|

### 💡 Claves de examen

- **ECB** = MAL
    
- **GCM** = MEJOR opción actual (cifrado + integridad)
    
- **CTR/CBC** = comunes, seguros, según caso de uso
    

---

# 🛡️ 4. **Firmas digitales**

La criptografía asimétrica permite generar firmas digitales para:

- Validar la identidad del remitente
    
- Garantizar que el mensaje no ha sido modificado
    
- Evitar repudio del remitente
    

Tecnologías donde se usa:

- TLS/SSL
    
- PKI
    
- Certificados digitales
    
- Software firmado
    
- Blockchain
    
- PGP
    

---

# 🌍 5. **Aplicaciones modernas de criptografía**

|Área|Uso|
|---|---|
|**Internet (HTTPS/TLS)**|Cifrado + autenticación de webs|
|**VPNs (IPsec, OpenVPN)**|Túneles cifrados|
|**SSH**|Control remoto seguro|
|**Correo (PGP/GPG)**|Cifrado end-to-end|
|**WiFi (WPA2/3)**|AES-GCM|
|**Blockchain**|Firmas y claves públicas|
|**Cloud**|Cifrado en reposo y tránsito|

---

# 🧪 6. **Resumen final para exámenes**

- **Simétrico** → misma clave, rápido, problema: intercambio de claves
    
- **Asimétrico** → par de claves, lento, pero resuelve intercambio
    
- **AES** → estándar actual
    
- **DES/3DES** → obsoletos
    
- **GCM** → modo moderno con integridad
    
- **RSA/ECC** → criptografía asimétrica para seguridad web y firmas
    
- **HTTPS usa ambos**:
    
    - Asimétrico para el handshake
        
    - Simétrico (AES) para el tráfico real
