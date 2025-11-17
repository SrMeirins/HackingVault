Las redes pueden estructurarse de diferentes maneras según su alcance y tecnología. Para clasificarlas se utilizan **tipos** y **topologías**, lo que facilita entender su propósito y funcionamiento.  
Se pueden dividir en **terminología común** (lo que más se usa en la práctica) y **terminología académica o de libro** (útil conocer, aunque rara vez se aplica directamente).

---

### **Terminología común**

|Tipo de red|Definición|
|---|---|
|**WAN (Wide Area Network)**|Red de gran alcance. Ej: Internet.|
|**LAN (Local Area Network)**|Red interna limitada a un edificio u oficina.|
|**WLAN (Wireless LAN)**|Red interna accesible vía Wi-Fi.|
|**VPN (Virtual Private Network)**|Red virtual que conecta varios sitios o usuarios como si estuvieran en la misma LAN.|

#### **WAN**

- Una **WAN** conecta varias LANs entre sí.
    
- Se identifica por usar protocolos de enrutamiento específicos (ej: **BGP**) y por usar direcciones IP públicas o no RFC1918.
    
- Puede existir una **WAN interna** (intranet) aislada de Internet.
    

#### **LAN / WLAN**

- Una **LAN** asigna direcciones IP locales (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
    
- Una **WLAN** es básicamente una LAN con conexión inalámbrica, lo que añade una consideración de seguridad.
    

#### **VPN**

- Permite conectarse virtualmente a otra red.
    
- Tipos principales:
    
    1. **Site-to-Site VPN:** Conecta redes completas entre sí (usualmente routers/firewalls).
        
    2. **Remote Access VPN:** El cliente se conecta como si estuviera dentro de la red remota.
        
        - **Split-Tunnel:** Solo ciertas rutas pasan por la VPN; el resto del tráfico usa Internet directamente.
            
    3. **SSL VPN:** Se ejecuta desde el navegador; puede transmitir aplicaciones o sesiones completas de escritorio.
        

---

### **Terminología académica / de libro**

|Tipo de red|Definición|
|---|---|
|**GAN (Global Area Network)**|Red global, como Internet.|
|**MAN (Metropolitan Area Network)**|Red regional que conecta varias LANs cercanas geográficamente.|
|**PAN (Personal Area Network)**|Red personal, conecta dispositivos cercanos (ej: mediante cable).|
|**WPAN (Wireless Personal Area Network)**|Red personal inalámbrica (Bluetooth, Wireless USB).|

#### **GAN**

- Red mundial, como Internet.
    
- Puede ser privada (empresas internacionales) y utiliza infraestructuras de fibra óptica y cables submarinos.
    

#### **MAN**

- Conecta varias LANs en la misma ciudad o región.
    
- Alta velocidad gracias a fibra óptica y routers de alto rendimiento.
    
- Puede conectarse a redes más amplias (WAN o GAN).
    

#### **PAN / WPAN**

- **PAN:** Red muy cercana, conecta dispositivos por cable (smartphones, ordenadores, etc.).
    
- **WPAN:** Versión inalámbrica, típica Bluetooth o Wireless USB.
    
    - **Piconet:** Red WPAN por Bluetooth.
        
- Usos típicos: IoT, automatización del hogar, comunicación de dispositivos con baja tasa de datos.
    

---

✅ **Resumen visual mental:**

- **WAN → Gran alcance → Internet / múltiples LANs.**
    
- **LAN/WLAN → Alcance local → Oficina/casa.**
    
- **VPN → Virtual → Conexión segura entre redes o usuarios.**
    
- **GAN → Global, MAN → Regional, PAN/WPAN → Personal/cercana.**