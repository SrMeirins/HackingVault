---

# 🟦 **APUNTES AMPLIADOS – Vendor Specific + VLANs (Cisco, VLANs, 802.1Q, Hopping, VXLAN, etc.)**

---
# 🟩 **1. Cisco IOS – Qué es y cómo funciona**

### 📝 **Qué es Cisco IOS**

Cisco IOS (Internetwork Operating System) es el sistema operativo que usan routers y switches Cisco.  
Piensa en él como el _“Windows o Linux del hardware de red”_.

Es responsable de:

- Gestionar la comunicación entre dispositivos.
    
- Aplicar seguridad.
    
- Controlar el tráfico.
    
- Mantener servicios como routing, switching y gestión remota.
    

### 📌 **Versiones**

Cisco IOS tiene muchas versiones porque:

- Cada modelo de dispositivo requiere funciones diferentes.
    
- Algunas incluyen protocolos concretos.
    
- Algunas versiones son más ligeras para equipos pequeños.
    

### ⭐ Funciones importantes

IOS incluye muchas capacidades modernas:

|Función|Explicación sencilla|
|---|---|
|**IPv6**|Permite manejar direcciones del protocolo más nuevo.|
|**QoS**|Prioriza tráfico (voz, vídeo, etc.).|
|**Seguridad (encriptación, autenticación)**|Protege comunicaciones y accesos.|
|**VPLS**|Crear redes virtuales de nivel 2 sobre grandes distancias.|
|**VRF**|Varias tablas de routing en un mismo equipo para separar tráfico.|

---

## 🟩 **2. Cómo administrar Cisco IOS**

### 🖥️ **CLI (Command Line Interface)** – El método más usado

La CLI es como una terminal donde escribes comandos.  
Permite control total y es la forma estándar de gestionar equipos Cisco.

### 🖼️ **GUI**

Algunos modelos incluyen interfaces gráficas, pero son menos usadas por administradores profesionales.

### 🌐 **Protocolos soportados (resumen)**

|Tipo|Para qué sirve|Ejemplo|
|---|---|---|
|**Routing**|Decidir por dónde viajan los paquetes|OSPF, BGP|
|**Switching**|Cómo se comportan switches|STP, VTP|
|**Servicios**|Servicios para clientes|DHCP|
|**Seguridad**|Controlar quién accede a qué|ACLs|

---

# 🟩 **3. Tipos de contraseñas en Cisco IOS**

Cisco IOS usa varios niveles de contraseñas.

Imagina Cisco como un edificio con varias puertas:

|Tipo|Nivel de acceso|Explicación|
|---|---|---|
|**User**|Entrada básica|Acceso inicial para usuarios simples.|
|**Enable**|“Puerta VIP”|Permite entrar a modo privilegiado (`enable`).|
|**Secret**|Protege servicios sensibles|Suele usarse para acceso remoto.|
|**Enable Secret**|Más segura|Reemplaza a `enable` pero cifrada. Siempre usar esta.|

> 📌 Nota: `enable secret` **siempre sobrescribe** a `enable password`.

---

# 🟦 **4. VLANs
## 🟩 ¿Qué es una VLAN? 

Una VLAN es **una red lógica dentro de un switch físico**.

Metáfora:  
👉 _Un switch es como un edificio de oficinas. Sin VLANs, todas las oficinas comparten el mismo pasillo._  
👉 _Con VLANs, cada grupo de oficinas tiene su propio pasillo independiente._

### Beneficios claros:

- **Organización**: separar departamentos aunque estén en lugares físicos distintos.
    
- **Seguridad**: un usuario de Marketing no puede “escuchar” el tráfico de Finanzas.
    
- **Menos congestión**: cada VLAN tiene su propio dominio de broadcast.
    
- **Facilidad de administración**: no importa dónde esté físicamente un equipo.
    

---

## 🟩 Ejemplo práctico

El administrador debe dividir una empresa en departamentos:

|Departamento|VLAN ID|Subnet|
|---|---|---|
|Servers|10|192.168.1.0/24|
|C-level|20|192.168.2.0/24|
|Finance|30|192.168.3.0/24|
|...|...|...|

Cada VLAN = un broadcast domain independiente.

---

# 🟦 **5. VLAN Ranges (normal y extended)**

Los switches Cisco permiten VLANs desde **1 a 4094**.

|Rango|Uso|
|---|---|
|**1-1005**|Normal range (guardadas en _vlan.dat_)|
|**1002-1005**|Reservadas (Token Ring, FDDI)|
|**1006-4094**|Extended range (no se guardan en _vlan.dat_)|

---

# 🟦 **6. VLAN Membership – Static vs Dynamic**

### 🔹 **Static VLANs (la forma segura y habitual)**

Asignas manualmente un puerto a una VLAN.  
Si conectas un PC a ese puerto → automáticamente pertenece a esa VLAN.

### 🔹 **Dynamic VLANs**

El switch decide la VLAN basándose en MAC o políticas.  
Usan VMPS (“servidor que guarda qué MAC pertenece a qué VLAN”).

**Problema de seguridad:**  
Un atacante puede falsificar MAC addresses → entrar a VLANs ajenas.

---

# 🟦 **7. Access Ports vs Trunk Ports**

|Tipo de puerto|Función|
|---|---|
|**Access**|Sólo lleva tráfico de 1 VLAN. Ideal para PCs.|
|**Trunk**|Lleva tráfico de muchas VLANs. Conecta switches entre sí.|

Los trunks usan protocolos de etiquetado para diferenciar las VLANs.

---

# 🟩 **8. VLAN Tagging (cómo los switches identifican la VLAN)**

Los Ethernet frames normales **no tienen información de VLAN**.  
Por eso se usan protocolos de tagging:

## 1️⃣ **ISL (antiguo, Cisco)**

Encapsula completamente el frame. Ya casi no se usa.

## 2️⃣ **802.1Q (estándar actual)**

Añade un pequeño header dentro del frame:

- **TPID** (marca 0x8100 → “esto tiene VLAN”)
    
- **TCI** (PCP, DEI, VID)
    
- **VID** = VLAN ID (12 bits → 4094 VLANs posibles)
    

### 📌 **Conceptos clave**

- **Tagged** → Frame lleva información de VLAN.
    
- **Untagged** → No lleva etiqueta (normalmente VLAN nativa).
    

---

# 🟦 **9. VLAN en NICs (tarjetas de red) – Linux & Windows**

## 🐧 En Linux

1. Cargar módulo 8021q:
    

```
sudo modprobe 8021q
```

2. Crear interfaz VLAN:
    

```
sudo ip link add link eth0 name eth0.20 type vlan id 20
```

3. Asignar IP y activar:
    

```
sudo ip addr add 192.168.1.1/24 dev eth0.20
sudo ip link set up eth0.20
```

---

## 🪟 En Windows

VLANs se configuran desde:

```
Device Manager → Adapter Properties → VLAN ID
```

O por PowerShell:

```
Set-NetAdapter -Name "Ethernet 2" -VlanID 10
```

---

# 🟦 **10. Analizar VLAN traffic (Wireshark)**

Filtros:

- Ver frames VLAN:
    
    ```
    vlan
    ```
    
- Filtrar por VLAN concreta:
    
    ```
    vlan.id == 10
    ```
    

Enumerar VLANs de un PCAP:

```
tshark -r file.pcap -T fields -e vlan.id | sort -n -u
```

---

# 🟦 **11. Seguridad: VLAN Attacks**

## 🟥 VLAN Hopping (con DTP)

El atacante engaña al switch para crear un **trunk** con su PC.  
Así recibe tráfico de **todas** las VLANs.

Requiere:

- Puerto accesible físicamente.
    
- DTP activado (por defecto en Cisco antiguos).
    

Herramientas: **Yersinia**

---

## 🟥 Double Tagging Attack

El atacante envía un frame con **dos etiquetas VLAN**.

Funciona porque:

- El switch elimina la etiqueta de la VLAN nativa.
    
- La segunda etiqueta queda intacta → El frame salta a otra VLAN.
    

Limitación:

- Sólo funciona si el atacante está en la **misma VLAN que la VLAN nativa**.
    

---

# 🟦 **12. VXLAN – VLANs evolucionadas (para data centers)**

### ¿Por qué existe VXLAN?

Las VLANs sólo permiten 4094 IDs → insuficiente para grandes centros de datos.

### VXLAN añade:

- **Segment ID de 24 bits** → 16 millones de segmentos.
    
- Permite extender redes de Capa 2 sobre Capa 3.
    
- Ideal para virtualización, cloud y entornos multitenant.
    

Funciona como un “túnel” que encapsula tráfico L2 dentro de L3.

---

# 🟦 **13. CDP – Cisco Discovery Protocol**

Protocolo propietario de Cisco que:

- Anuncia información entre dispositivos vecinos.
    
- Muy útil para inventario y troubleshooting.
    
- Puede ser un riesgo si se expone hacia redes inseguras.
    

Información típica:

- Nombre del dispositivo
    
- IP
    
- Plataforma
    
- Versión de IOS
    
- Puertos usados
    

---

# 🟦 **14. STP – Spanning Tree Protocol**

Evita **bucles en la red**, que causarían caos y congestión.

STP:

- Detecta enlaces redundantes.
    
- “Bloquea” algunos para evitar loops.
    
- Versiones modernas: RSTP (más rápida).
    

---