## **1️⃣ Qué es un Proxy**

- Dispositivo o servicio que **intercepta y actúa como mediador** entre un cliente y un destino.
    
- Clave: debe **inspeccionar el tráfico**.
    
- Si solo reenvía tráfico, es un **gateway**, no un proxy.
    

**Confusiones comunes:**

- Cambiar IP ≠ usar proxy (mucha gente confunde VPN con proxy).
    
- Proxy opera normalmente en **Capa 7 (Aplicación)** del modelo OSI.
    

---

## **2️⃣ Tipos principales de Proxies**

1. **Forward / Dedicated Proxy**
    
2. **Reverse Proxy**
    
3. **Transparent / Non-Transparent Proxy**
    

---

## **3️⃣ Forward Proxy (Proxy Directo / Dedicado)**

**Concepto:**

- Cliente → Proxy → Destino
    
- Filtra **tráfico saliente** y puede bloquear contenido.
    

**Usos:**

- Corporativos: equipos internos sin acceso directo a Internet.
    
- Seguridad: filtrar malware, controlar tráfico web.
    
- Pentesting: interceptar/modificar HTTP(S) con herramientas como **Burp Suite**.
    

**Notas importantes:**

- Navegadores IE/Edge/Chrome usan **System Proxy** → malware puede detectarlo.
    
- Firefox usa **libcurl**, malware debe buscar configuración específica (menos probable).
    
- DNS puede ser usado como C2, pero tráfico monitorizado es detectado rápido.
    

---

## **4️⃣ Reverse Proxy (Proxy Inverso)**

**Concepto:**

- Cliente → Reverse Proxy → Servidores internos
    
- Filtra **tráfico entrante**, protege la infraestructura interna y distribuye carga.
    

**Usos:**

- Protección contra DDoS (**Cloudflare**).
    
- Actuar como **WAF**: inspección de tráfico malicioso (**ModSecurity**, Cloudflare).
    
- Pentesting: usar reverse proxies en endpoints comprometidos para **evadir firewalls o IDS**.
    

---

## **5️⃣ Transparent vs Non-Transparent Proxy**

|Tipo|Cliente lo nota|Configuración|Uso típico|
|---|---|---|---|
|**Transparent**|❌ No|Ninguna|Interceptación invisible, control parental, auditoría silenciosa|
|**Non-Transparent**|✔ Sí|Manual (navegador, SO)|Forward proxy corporativo, Burp Suite, SOCKS proxy|

**Resumen:**

- **Transparent:** intercepta sin que el cliente se entere.
    
- **Non-Transparent:** requiere configuración explícita.
    

---

## **6️⃣ Resumen visual rápido**

**Forward Proxy**

```
Cliente → Proxy → Internet
Filtra tráfico saliente, controla navegación
Ej: Burp Suite, Proxy corporativo
```

**Reverse Proxy**

```
Internet → Proxy → Servidor interno
Filtra tráfico entrante, protege infraestructura
Ej: Cloudflare, Nginx, ModSecurity
```

**Transparent Proxy**

- Intercepta tráfico sin avisar al cliente
    

**Non-Transparent Proxy**

- Cliente debe configurar proxy manualmente
