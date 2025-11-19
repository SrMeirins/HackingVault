El **modelo OSI** fue creado como **referencia** para que distintos sistemas y dispositivos puedan comunicarse entre sí de manera **compatibles y estructurada**.  
Se divide en **7 capas jerárquicas**, que representan **fases de la conexión** por las que pasan los paquetes de datos.

---

## **1️⃣ Función de cada capa**

|Capa|Función principal|Comentario práctico|
|---|---|---|
|**7. Aplicación**|Controla entrada/salida de datos y funciones de la aplicación|Ej: HTTP, FTP, correo, navegador|
|**6. Presentación**|Convierte datos de formato específico del sistema a formato estándar independiente de la aplicación|Ej: cifrado, compresión, codificación de caracteres|
|**5. Sesión**|Gestiona la conexión lógica entre sistemas y evita cortes o errores|Establece, mantiene y cierra sesiones de comunicación|
|**4. Transporte**|Controla la transmisión de datos **end-to-end**; segmenta datos, detecta y evita congestión|TCP (fiable), UDP (rápido)|
|**3. Red**|Dirige paquetes de datos de origen a destino a través de la red|IP, enrutamiento, circuitos conmutados|
|**2. Enlace de datos**|Asegura transmisión confiable y sin errores en el medio físico; organiza bits en **frames**|Ethernet, MAC, control de errores|
|**1. Física**|Transmite los bits como señales eléctricas, ópticas o electromagnéticas|Cables, fibra, Wi-Fi, ondas de radio|

---

## **2️⃣ Orientación de las capas**

- **Capas 5‑7 → Orientadas a la aplicación:** interacción con el usuario y programas.
    
- **Capas 2‑4 → Orientadas al transporte:** garantizan entrega de datos, control de errores y direccionamiento.
    

💡 **Idea clave:**  
Cada capa usa los **servicios de la capa inferior** y ofrece servicios a la **capa superior**.

---

## **3️⃣ Comunicación entre sistemas**

Cuando dos sistemas se comunican:

1. **Sistema emisor:**
    
    - Datos viajan de **capa 7 → capa 1** (Application → Physical)
        
    - Cada capa añade información (headers, segmentación, control de errores, etc.)
        
2. **Sistema receptor:**
    
    - Datos viajan de **capa 1 → capa 7** (Physical → Application)
        
    - Cada capa **desempaqueta** la información y procesa su función específica
        

✅ **Resultado:** comunicación confiable, segura y organizada.

---

## **4️⃣ Resumen visual rápido**

```
Capa 7 - Aplicación    ← Interacción con programas
Capa 6 - Presentación   ← Formato / cifrado / compresión
Capa 5 - Sesión         ← Mantener conexión estable
Capa 4 - Transporte     ← Segmentación, control de flujo (TCP/UDP)
Capa 3 - Red            ← Enrutamiento, IP
Capa 2 - Enlace de datos← Frames, MAC, corrección de errores
Capa 1 - Física         ← Bits transmitidos por cables/ondas
```

**Flujo de datos en comunicación:**

```
Emisor: 7 → 1  →  Medio  →  Receptor: 1 → 7
```

---

## **5️⃣ Tip Vault**

- Cada paquete pasa al menos **dos veces por todas las capas** (emisor y receptor).
    
- Conocer **función de cada capa** es fundamental para:
    
    - Pentesting de redes
        
    - Sniffing y análisis de tráfico
        
    - Diagnóstico de problemas de conexión
        