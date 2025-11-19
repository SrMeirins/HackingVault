### **1. Concepto de Topología de Red**

La **topología de red** define cómo se conectan los dispositivos (hosts) y los nodos de red (switches, routers, hubs, etc.).  
Determina:

- Qué dispositivos se usan.
    
- Cómo los datos se transmiten.
    
- Qué método de acceso se aplica al medio de transmisión.
    

**Tipos de topología:**

- **Física:** disposición real de cables y nodos.
    
- **Lógica:** forma en que circula la información, independientemente del cableado físico.
    

---

### **2. Elementos clave en una red**

|Categoría|Ejemplos|Función|
|---|---|---|
|**Conexiones**|Cableadas: coaxial, par trenzado, fibra óptica. Inalámbricas: Wi-Fi, celular, satélite, Bluetooth.|Medio para transmitir datos.|
|**Nodos / Dispositivos**|Repetidores, hubs, bridges, switches, routers, gateways, firewalls.|Puntos de conexión que envían, reciben o reenvían datos.|
|**Hosts**|Computadoras, servidores, smartphones, IoT|Dispositivos que usan la red para comunicarse.|

---

### **3. Tipos de Topologías de Red**

#### **a) Point-to-Point (Punto a Punto)**

- Conexión directa entre **2 dispositivos**.
    
- Muy simple, fiable y de baja latencia.
    
- Ej: telefonía tradicional, enlace dedicado entre dos routers.
    
- **Nota:** No confundir con P2P (Peer-to-Peer).
    

#### **b) Bus**

- Todos los dispositivos comparten **un único cable**.
    
- Solo un host transmite a la vez; los demás escuchan.
    
- No hay nodo central.
    
- Limitación: colisiones de datos posibles si dos envían al mismo tiempo.
    

#### **c) Star (Estrella)**

- Cada host se conecta a un **nodo central** (switch, hub o router).
    
- El nodo central gestiona todo el tráfico.
    
- Ventaja: fácil de administrar y aislar fallos.
    
- Desventaja: si el nodo central falla, toda la red cae.
    

#### **d) Ring (Anillo)**

- Cada host se conecta a **dos nodos adyacentes**, formando un círculo.
    
- Los datos circulan en una dirección.
    
- Puede usar **token** para controlar el acceso y evitar colisiones.
    
- Lógicamente puede simularse sobre una topología estrella.
    

#### **e) Mesh (Malla)**

- Cada nodo puede conectarse a varios otros.
    
- **Malla total:** todos conectados entre sí → máxima fiabilidad.
    
- **Malla parcial:** algunos nodos conectados solo a ciertos nodos → equilibrio entre costo y redundancia.
    
- Muy usada en WANs o MANs donde la disponibilidad es crítica.
    

#### **f) Tree (Árbol)**

- Extensión de la estrella con jerarquía de nodos.
    
- Los nodos superiores actúan como distribuidores de tráfico hacia nodos inferiores.
    
- Ideal para redes grandes, edificios corporativos o infraestructuras MAN.
    

#### **g) Hybrid (Híbrida)**

- Combinación de **dos o más topologías** básicas.
    
- Flexible, se adapta a redes complejas.
    
- Ej: estrella + bus o árbol + malla.
    

#### **h) Daisy Chain (Cadena de margarita)**

- Los nodos se conectan **en serie**.
    
- Los datos pasan de un nodo al siguiente.
    
- Muy usada en **automatización y control industrial**.
    

---

### **4. Resumen Visual y Conceptual**

|Topología|Característica clave|Ventaja|Desventaja|
|---|---|---|---|
|Point-to-Point|Conexión directa 2 hosts|Muy fiable|Solo 2 dispositivos|
|Bus|Cable compartido|Sencilla|Colisiones, limitado en distancia|
|Star|Nodo central|Fácil administración|Nodo central crítico|
|Ring|Circular, token|Control de acceso|Fallo de un nodo afecta la red (si no hay redundancia)|
|Mesh|Conexiones múltiples|Alta fiabilidad|Costosa en cableado y gestión|
|Tree|Jerárquica|Escalable|Complejidad en nodos superiores|
|Hybrid|Combinación|Flexible|Compleja de diseñar|
|Daisy Chain|Serie de nodos|Fácil de extender|Cada nodo depende del anterior|

---

✅ **Tips**

- Piensa en **física vs lógica**: la disposición real puede diferir del flujo de datos.
    
- Las topologías más usadas hoy son **estrella**, **malla** y **híbridas**.
    
- Saber la topología ayuda a entender **posibles fallos, cuellos de botella y rutas de ataque**.
    