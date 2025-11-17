La **autenticación** es el proceso mediante el cual un sistema verifica que una entidad (usuario, dispositivo o servicio) es realmente quien dice ser.  
En redes y sistemas distribuidos, esto es **fundamental** para evitar accesos no autorizados, ataques de suplantación y manipulación de datos.

Los **protocolos de autenticación** estandarizan este proceso, garantizando que múltiples sistemas puedan interoperar de forma segura y consistente.

---

## 🎯 **¿Por qué son necesarios los protocolos de autenticación?**

- **Verificar identidades** de forma fiable → Evita accesos no autorizados.
    
- **Proteger comunicaciones** → Muchos protocolos encapsulan o integran cifrado.
    
- **Evitar ataques comunes** → MITM, replay, credenciales robadas, suplantación.
    
- **Estándares comunes** → Permiten que sistemas heterogéneos trabajen juntos.
    
- **Confidencialidad e integridad** → La información intercambiada queda protegida.
    

Dado este contexto, presentamos los protocolos más relevantes utilizados hoy en día.

---

# 🔐 **Principales Protocolos de Autenticación**

A continuación, una lista estructurada con explicación clara y moderna de cada protocolo.

---

## 🏛️ **Kerberos**

- **Tipo:** Autenticación basada en tickets y en un _Key Distribution Center_ (KDC).
    
- **Dónde se usa:** Entornos de dominio (Windows AD).
    
- **Idea clave:** En lugar de enviar credenciales repetidamente, se usan tickets con tiempo limitado.
    
- **Ventajas:**  
    ✔ Evita retransmisión de contraseñas  
    ✔ Autenticación mutua  
    ✔ Seguro ante MITM (si está bien implementado)
    

---

## 🔑 **SRP (Secure Remote Password)**

- **Tipo:** Autenticación basada en contraseña sin enviar la contraseña nunca.
    
- **Protecciones:** Contra MITM, eavesdropping, replay.
    
- **Ventaja clave:** Permite verificar contraseñas sin exponerlas ni siquiera en forma hash durante la autenticación.
    

---

## 🔒 **SSL / TLS**

- **Tipo:** Protocolos criptográficos.
    
- **Objetivo:** Autenticar servidor (opcional cliente) + cifrar el canal.
    
- **Notas:**  
    ✔ SSL está obsoleto  
    ✔ TLS es el estándar actual  
    ✔ Se usa en HTTPS, SMTP seguro, IMAP seguro, etc.
    

---

## 🔑 **OAuth**

- **Tipo:** Autorización delegada.
    
- **Idea clave:** Permite que una aplicación acceda a datos en nombre de un usuario _sin conocer su contraseña_.
    
- **Ejemplos:** Login con Google, Facebook, GitHub.
    

---

## 🌐 **OpenID**

- **Tipo:** Autenticación federada.
    
- **Objetivo:** Un solo proveedor de identidad para múltiples servicios.
    
- **Ejemplo:** “Inicia sesión con tu cuenta de Google”.
    

---

## 🧾 **SAML**

- **Tipo:** Autenticación y autorización federadas basadas en XML.
    
- **Muy usado en:** Empresas y entornos corporativos (SSO entre servicios).
    

---

## 🔐 **2FA / MFA**

- **2FA:** Combina dos factores (algo que sabes, tienes o eres).
    
- **MFA:** Más de dos factores.
    
- **Ventajas:** Aumenta drásticamente la seguridad frente a robo de contraseñas.
    

---

## 🔐 **FIDO**

- **Objetivo:** Autenticación fuerte sin contraseñas (passwordless).
    
- **Ejemplos:** WebAuthn, llaves YubiKey, biometría hardware.
    

---

## 🔏 **PKI (Public Key Infrastructure)**

- **Base:** Certificados + claves públicas/privadas.
    
- **Rol:** Autenticar identidades basado en autoridades certificadoras (CAs).
    
- **Usos:** HTTPS, firmas digitales, S/MIME.
    

---

## 🔁 **SSO (Single Sign-On)**

- **Objetivo:** Un solo login → acceso a múltiples aplicaciones.
    
- **Protocolos usados:** SAML, OAuth2, OpenID Connect, Kerberos.
    

---

## 📝 **PAP (Password Authentication Protocol)**

- **Tipo:** Contraseña en texto claro.
    
- ❌ **Totalmente inseguro**, solo se usa en contextos legacy.
    

---

## 🔄 **CHAP (Challenge-Handshake Authentication Protocol)**

- **Idea:** Reto y respuesta → nunca envía la password.
    
- **Mejor que PAP, pero antiguo.**
    

---

## 💼 **EAP (Extensible Authentication Protocol)**

- **Marco**, no protocolo concreto.
    
- Permite múltiples métodos de autenticación (certificados, contraseñas, tarjetas…).
    
- Usado en entornos Wi-Fi empresariales (802.1X).
    

---

## 🐧 **SSH**

- **Tipo:** Protocolo seguro para administración remota.
    
- **Métodos de autenticación:** Clave pública, contraseña, certificados.
    
- **Protecciones:** Cifrado, autenticación mutua, integridad.
    

---

## 🌐 **HTTPS**

- **HTTP + TLS** para navegación segura.
    
- Autentica el servidor y protege todo el tráfico.
    

---

# 📡 **Protocolos Wi-Fi: LEAP vs PEAP**

### 🔵 **LEAP (obsoleto)**

- Desarrollado por Cisco.
    
- Mutual authentication + RC4.
    
- ❌ Vulnerable a ataques de diccionario y cracking de MSCHAPv2.
    
- Actualmente **desaconsejado**.
    

### 🟢 **PEAP**

- Variante de EAP usando TLS.
    
- Ventajas:  
    ✔ Autentica el servidor con certificado  
    ✔ Cifra MSCHAPv2 → más seguro  
    ✔ Soporta contraseñas, certificados, biometría
    

→ Reemplazó casi por completo a LEAP.

---

# 🔒 **Comparación general de contextos de uso**

|Protocolo|Para qué sirve|Nivel de seguridad|Comentarios|
|---|---|---|---|
|Kerberos|Dominios corporativos|Muy alto|Basado en tickets y KDC|
|OAuth|Autorización entre servicios|Alto|No es autenticación pura|
|OpenID|Identidad federada|Alto|Usado en web|
|SAML|SSO empresarial|Muy alto|XML y firmas digitales|
|PEAP|Autenticación Wi-Fi|Alto|Usa TLS|
|SSH|Acceso remoto|Muy alto|Amplio soporte|
|TLS|Cifrado + autenticación|Muy alto|Estándar moderno|

---

# 🔐 **Resumen conceptual final**

Los protocolos de autenticación buscan:

1. **Identificar entidades con fiabilidad.**
    
2. **Intercambiar credenciales o claves de forma segura.**
    
3. **Evitar que un atacante suplante, modifique o intercepte.**
    
4. **Integrarse fácilmente en sistemas distribuidos modernos.**
    

Mientras que protocolos como **TLS, SSH, Kerberos o SAML** se centran en autenticación segura a diferentes niveles, otros como **OAuth, OpenID o SSO** se enfocan en gestión de identidad y delegación de acceso.
