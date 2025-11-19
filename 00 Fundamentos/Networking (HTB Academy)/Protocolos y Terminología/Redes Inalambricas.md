# 🔷 1. Visión General de Redes Inalámbricas

Las redes inalámbricas permiten la comunicación entre dispositivos mediante **radiofrecuencia (RF)** sin cables físicos.  
Cada dispositivo incorpora un **adaptador WiFi** que transforma datos ⇄ señales RF.

### ▪ Ámbitos de uso

|Tipo|Tecnología|Alcance|Uso|
|---|---|---|---|
|WLAN|WiFi (802.11)|Hasta cientos de metros|Hogares, oficinas|
|WWAN|3G/4G/5G|Kilómetros|Telecomunicaciones|

### ▪ Requisitos para conectarse

- Estar dentro del rango RF.
    
- Conocer el **SSID**.
    
- Disponer de la **clave** o método de autenticación correcto.
    

---

# 🔷 2. Fundamentos Técnicos del WiFi

## 2.1. Bandas de Frecuencia

- **2.4 GHz** → Mayor alcance / mayor interferencia
    
- **5 GHz** → Menos alcance / más velocidad
    
- **6 GHz (WiFi 6E)** → Más limpio / baja saturación
    

## 2.2. Rol del Punto de Acceso (WAP)

Un WAP:

- Gestiona tráfico entre clientes.
    
- Conecta red inalámbrica ↔ red cableada.
    
- Asigna canales, modulación, seguridad.
    

## 2.3. Factores que afectan la señal

- Obstáculos físicos
    
- Ruido RF (otras redes, Bluetooth, microondas)
    
- Saturación del canal
    
- Potencia del AP
    

---

# 🔷 3. Proceso de Conexión (IEEE 802.11)

## 3.1. Etapas del Join Process

1. **Discovery** (beacons / probe requests)
    
2. **Autenticación** (Open/WEP/WPA/WPA2/WPA3)
    
3. **Asociación**
    
4. **(Opcional) 4-Way Handshake**
    

## 3.2. Association Request Frame

Incluye:

- MAC del cliente
    
- SSID solicitado
    
- Rates y canales soportados
    
- Protocolos de seguridad soportados
    

🔍 **Nota de pentester:**  
Aunque el SSID esté oculto, **aparece siempre en tramas de autenticación**.

---

# 🔷 4. Seguridad WEP — Diseño, Fallos y Ataques

## 4.1. Tipos de claves

|Variante|IV|Clave|
|---|---|---|
|WEP-40/64|24 bits|40 bits|
|WEP-104|24 bits|80 bits|

## 4.2. Problemas fundamentales

- IV muy corto → colisiones.
    
- RC4 vulnerable (FMS / KoreK / PTW).
    
- CRC inseguro → permite deducción de texto plano.
    

## 4.3. Handshake WEP

1. Cliente → request
    
2. AP → challenge
    
3. Cliente → challenge firmado
    
4. AP → valida
    

## 4.4. Ataques WEP

- Reinyección ARP
    
- Captura IVs
    
- Crackeo con aircrack-ng
    
- Explotación del CRC
    

---

# 🔷 5. WPA / WPA2 / WPA3

## 5.1. WPA / WPA2

Emplea TKIP (obsoleto) o **AES-CCMP (seguro)**.

### Modos:

- **WPA-Personal (PSK)**
    
- **WPA-Enterprise (802.1X + RADIUS)**
    

### Vulnerabilidades típicas:

- Captura de **4-Way Handshake**
    
- Ataques PMKID
    
- Rogue AP / Evil Twin
    
- Phishing en portales cautivos
    

## 5.2. WPA3

Incluye:

- SAE (Dragonfly)
    
- Protección contra ataques offline
    
- Forward secrecy real
    

---

# 🔷 6. Protocolos de Autenticación (EAP)

### LEAP

- Basado en clave compartida.
    
- Inseguro → crackeable mediante diccionario.
    

### PEAP

- Túnel TLS.
    
- Protege credenciales de usuario.
    

### EAP-TLS

- Basado en certificados.
    
- **Más seguro y recomendado.**
    

### Flujo con 802.1X

Cliente → AP (authenticator) → RADIUS / TACACS+

---

# 🔷 7. TACACS+ en Infraestructuras Wireless

Utilizado en entornos Enterprise para:

- Autenticación
    
- Autorización
    
- Accounting
    

La comunicación va **cifrada** (TLS/IPSec).  
Evita manipulación y exposición de credenciales.

---

# 🔷 8. Principales Ataques WiFi

## 8.1. Desasociación / Deauth Attack

Envío de tramas de Deauth para:

- Interrumpir conexiones
    
- Forzar handshake
    
- Preparar un MITM (Evil Twin)
    

Herramientas:

- aireplay-ng
    
- mdk3/mdk4
    
- Scapy
    

## 8.2. Rogue AP / Evil Twin

Crear un AP falso para capturar:

- Handshakes
    
- Credenciales WPA-Enterprise
    
- Tokens / cookies
    

## 8.3. PMKID Attack

Explotación de un PMKID expuesto sin necesidad de deauth.

## 8.4. WPS Attacks

- **Brute force PIN**
    
- Pixie Dust
    

---

# 🔷 9. Hardening de Redes Wireless

## 9.1. Configuración del AP

- Desactivar broadcast del SSID (solo seguridad por ocultación).
    
- Usar **WPA2-PSK (AES)** o mejor **WPA3**.
    
- Cambiar canal automático → manual para evitar interferencias.
    
- Reducir potencia de transmisión.
    

## 9.2. Control de Acceso

- Filtrado MAC (fácil de evadir, pero útil en entornos controlados).
    
- VLANs separadas: empleados / invitados / IoT.
    

## 9.3. Seguridad Avanzada

- Implementación de **EAP-TLS**.
    
- WIDS/WIPS para detección de Rogue APs.
    

## 9.4. Supervisión y Logs

- Captura y análisis de eventos inalámbricos.
    
- Alertas ante conexiones sospechosas.
    

---

# 🔷 10. Protocolos Complementarios Interrelacionados

### DHCP

Asignación automática de IPs  
Ataques:

- Rogue DHCP
    
- Starvation
    

### TCP/IP

Base de comunicación para todos los servicios.

### Firewalls Integrados

Bloqueo de tráfico no solicitado, reglas anti-DoS.

---

# 🔷 11. Resumen Operativo para Pentesting

|Objetivo|Técnica|Herramientas|
|---|---|---|
|Discovery|Escaneo RF|airodump-ng, kismet|
|Captura|Handshakes / IV|aireplay-ng, hcxdumptool|
|Deauth|Forzar reconexión|aireplay-ng -0|
|Crackeo|PSK / WEP|aircrack-ng, hashcat|
|MITM|Rogue AP|hostapd-wpe, wifiphisher|
|Post-exploitation|Pivoting interno|Responder, mitm6|
