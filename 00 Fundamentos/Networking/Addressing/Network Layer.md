La **Capa de Red (Network Layer)** se encarga de que los **paquetes de datos lleguen del emisor al receptor**, incluso si están en redes diferentes o no pueden conectarse directamente.

> Piensa en ella como el **“GPS” de los datos**: decide **a qué dirección ir** y **por qué ruta viajar**, pero no se preocupa por lo que los datos contienen.

---

## **1️⃣ Funciones principales**

1. **Direccionamiento lógico (Logical Addressing)**
    
    - Cada dispositivo recibe una dirección única: la **IP** (IPv4 o IPv6).
        
    - Esto permite que los datos **se dirijan al dispositivo correcto** aunque haya muchas redes de por medio.
        
2. **Enrutamiento (Routing)**
    
    - Decide **por dónde deben pasar los paquetes** para llegar al destino.
        
    - Utiliza **routers y tablas de enrutamiento** para elegir la mejor ruta.
        
    - Los paquetes se envían de **nodo en nodo**, como si pasaran por varias estaciones hasta llegar a la meta.
        

> 💡 Nota: Los routers solo reenvían paquetes; **no leen ni modifican los datos de la capa superior**.

---

## **2️⃣ Protocolos más importantes de la Capa 3**

|Protocolo|Qué hace|
|---|---|
|**IPv4 / IPv6**|Direccionamiento y envío de paquetes de red|
|**IPsec**|Protege y cifra los datos entre redes|
|**ICMP**|Envía mensajes de control, como _ping_ o notificaciones de error|
|**IGMP**|Gestiona comunicación con grupos multicast|
|**RIP**|Protocolo simple para decidir rutas (basado en saltos)|
|**OSPF**|Protocolo avanzado para encontrar la ruta más corta y eficiente|

---

## **3️⃣ Cómo funciona la Capa 3 (ejemplo práctico)**

1. Tu computadora quiere enviar datos a otra en otra ciudad.
    
2. La **capa de red** agrega la **dirección IP de destino** al paquete.
    
3. El paquete llega al **primer router**, que decide a qué **siguiente router** enviarlo.
    
4. Esto se repite hasta que el paquete llega a la **red destino**.
    
5. Una vez en la red correcta, el paquete sube a la **capa de transporte** y luego a la aplicación.
    

> 📝 Resumen visual:

```
Emisor → Router 1 → Router 2 → Router 3 → Receptor
```

---

## **4️⃣ Tips para principiantes**

- La **Capa 3 es como el GPS y las señales de tráfico**: guía los datos, pero no sabe qué hay dentro del paquete.
    
- Todo router trabaja en **capa 3**.
    
- Esta capa permite **comunicar diferentes redes**, incluso si usan direcciones distintas.
    
- Los paquetes intermedios **no llegan a capas superiores** (como transporte o aplicación) hasta el destino final.