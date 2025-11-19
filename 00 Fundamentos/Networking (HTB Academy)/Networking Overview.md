### 1️⃣ Concepto Básico

- Una **red** permite que dos o más computadoras se comuniquen.
    
- Redes se diferencian por:
    
    - **Topologías:** Mesh, Tree, Star.
        
    - **Medios:** Ethernet, fibra, coaxial, inalámbrico.
        
    - **Protocolos:** TCP, UDP, IPX.
        
- Comprender redes es crucial para pentesters: un error de red puede ocultar vulnerabilidades o malinterpretar resultados.
    

---

### 2️⃣ Redes Planas vs Segmentadas

- **Red plana (flat network):**
    
    - Fácil de montar y fiable operativamente.
        
    - Vulnerable: un atacante puede moverse libremente.
        
- **Red segmentada:**
    
    - Divide la red en subredes más pequeñas.
        
    - Añade capas de defensa.
        
    - Ejemplos de defensas:
        
        - ACLs → “cercas” que limitan acceso.
            
        - IDS → detecta escaneos o actividad sospechosa.
            
        - Documentar cada red → permite monitoreo más eficiente.
            

---

### 3️⃣ Subnetting y Errores Comunes

- Muchas redes usan **/24** (255.255.255.0), que permite que los 256 hosts puedan comunicarse entre sí.
    
- Usar subredes más pequeñas (/25, /26) puede aislar hosts.
    
- Error común: pentesters confunden hosts en diferentes subredes y reportan servicios como “offline”.
    

---

### 4️⃣ Analogía con el Correo

- Internet = sistema de envío de paquetes.
    
- Router = “oficina local” que envía paquetes.
    
- ISP = oficina central que busca la dirección final (DNS).
    
- FQDN (ej. `www.hackthebox.eu`) = dirección del edificio.
    
- URL (ej. `https://www.hackthebox.eu/floor2/office3`) = dirección completa, incluye “piso, oficina y destinatario”.
    

---

### 5️⃣ Buenas Prácticas de Segmentación

- Cada tipo de dispositivo en su propia subred:
    
    - **Web server** → DMZ (acceso controlado desde internet).
        
    - **Workstations** → red interna separada con firewall host-based.
        
    - **Switches y routers** → red administrativa.
        
    - **IP Phones** → red propia (prioridad de tráfico, seguridad).
        
    - **Printers** → red propia (difícil de asegurar, riesgo de persistencia y robo de credenciales).
        