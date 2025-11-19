El **modelo TCP/IP** (también llamado _Internet Protocol Suite_) es un **modelo en capas** diseñado para la comunicación en Internet.  
Su nombre proviene de sus protocolos más importantes: **TCP (Transporte)** e **IP (Red)**.

> Nota: TCP/IP es **práctico y real**, mientras que OSI es más teórico.

---

## **1️⃣ Capas del TCP/IP**

|Capa|Función principal|Comentario práctico|
|---|---|---|
|**4. Aplicación**|Permite que las aplicaciones accedan a los servicios de la red y define los protocolos de intercambio de datos|Ej: HTTP, FTP, SMTP, DNS|
|**3. Transporte**|Garantiza la comunicación de extremo a extremo entre aplicaciones: **TCP** (fiable) / **UDP** (rápido, sin confirmación)|TCP controla flujo, errores y conexión; UDP es más rápido y simple|
|**2. Internet**|Encargada del direccionamiento lógico (IP), empaquetado y enrutamiento de datos|Determina a qué host y red debe llegar cada paquete|
|**1. Link (Acceso a Red)**|Coloca los paquetes en el medio físico y los recibe|Independiente del tipo de red, formato de trama o medio (Ethernet, Wi-Fi, fibra…)|

---

## **2️⃣ Comparación OSI vs TCP/IP**

|Característica|OSI|TCP/IP|
|---|---|---|
|Número de capas|7|4|
|Enfoque|Teórico, detallado|Práctico, basado en protocolos reales|
|Capas combinadas|Aplicación + Presentación + Sesión → Aplicación TCP/IP|Sí|
|Uso|Aprendizaje y análisis de tráfico|Internet real, redes privadas y públicas|

💡 **Idea clave:** TCP/IP combina varias capas de OSI y se centra en la **funcionalidad real** para que cualquier aplicación transfiera datos a cualquier host.

---

## **3️⃣ Tareas principales de TCP/IP y protocolos involucrados**

|Tarea|Protocolo|Descripción|
|---|---|---|
|**Direccionamiento lógico**|IP|Permite identificar hosts y redes; maneja subredes, clases de red y CIDR|
|**Enrutamiento**|IP|Decide por dónde pasarán los paquetes hasta llegar al destino, incluso si el remitente no conoce su ubicación exacta|
|**Control de errores y flujo**|TCP|Mantiene la conexión entre emisor y receptor; envía mensajes de control para verificar la integridad de la comunicación|
|**Soporte a aplicaciones**|TCP / UDP|Puertos distinguen aplicaciones y sus conexiones de red|
|**Resolución de nombres**|DNS|Traduce nombres de dominio (FQDN) a direcciones IP para localizar hosts en Internet|

---

## **4️⃣ Cómo funciona TCP/IP en la práctica**

1. **Aplicación** → genera datos (ej. navegador solicita página web).
    
2. **Transporte** → TCP segmenta los datos y asegura entrega; UDP envía datagramas rápidos.
    
3. **Internet** → IP añade dirección de destino y origen, prepara el paquete para enrutamiento.
    
4. **Link** → Se convierte en trama física y se envía por el medio (Ethernet, Wi-Fi, fibra).
    

> Al receptor le llega: **Link → Internet → Transporte → Aplicación**  
> Cada capa “desempaqueta” su parte y procesa los datos correspondientes.

---

## **5️⃣ Tips Vault / Recordatorio rápido**

- TCP/IP = **modelo real → Internet y redes privadas**
    
- OSI = **modelo teórico → análisis y estudio**
    
- IP → se encarga de **direccionamiento y enrutamiento**
    
- TCP → se encarga de **control de errores, flujo y conexión**
    
- UDP → rápido, sin confirmación, ideal para streaming o VoIP
    
- DNS → convierte **nombre de host → IP**