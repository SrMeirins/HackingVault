## **1️⃣ ¿Qué es Android?**

**Definición rápida:**

Android es un **sistema operativo móvil** diseñado para dispositivos con pantalla táctil (teléfonos, tablets), basado en un kernel de Linux modificado y desarrollado por el **Open Handset Alliance**, patrocinado comercialmente por Google.

**Componentes clave:**

- **GMS (Google Mobile Services):** Suite de apps propietarias (Google Play, Chrome, Gmail…)
    
- **Distribución de apps:** Google Play, Amazon Appstore, Samsung Galaxy Store, Huawei AppGallery, F-Droid, APKMirror, APKPure.
    
- **Dispositivos:** Smartphones, tablets, Smart TVs, wearables, algunos dispositivos IoT.
    

**💡 Nota Pentest:**  
Conocer GMS y tiendas alternativas permite identificar **vectores de ataque en apps no oficiales** y riesgos asociados a aplicaciones de terceros.

---

## **2️⃣ Historia de Android**

**Línea temporal resumida:**

|Año|Evento clave|
|---|---|
|2003|Fundación de Android Inc. (Rubin, Miner, Sears, White)|
|2005|Google adquiere Android (~$50M)|
|2007|Primer prototipo sin touchscreen, teclado QWERTY físico|
|2008|HTC Dream / T-Mobile G1, primer dispositivo comercial Android|
|2009-2010|Versiones Cupcake, Donut, Eclair, Froyo|
|2010|Lanzamiento Nexus|
|2013|Ediciones Google Play de fabricantes terceros|
|2014|Android One para fabricantes de bajo costo|
|2016|Google lanza Pixel / Pixel XL|
|2019|Android 10, fin de nombres de postres|

**💡 Nota Pentest:**  
Versiones antiguas pueden tener **vulnerabilidades conocidas**, especialmente pre-Android 10.

---

## **3️⃣ Versiones de Android (resumen rápido)**

|Nombre|Versión|API|Año|
|---|---|---|---|
|Android 1.0 – 1.1|1.0 – 1.1|1 – 2|2008-2009|
|Cupcake – Froyo|1.5 – 2.2.3|3 – 8|2009-2010|
|Gingerbread – Ice Cream Sandwich|2.3 – 4.0.4|9 – 15|2010-2011|
|Jelly Bean – KitKat|4.1 – 4.4W.2|16 – 20|2012-2014|
|Lollipop – Marshmallow|5.0 – 6.0.1|21 – 23|2014-2015|
|Nougat – Oreo|7.0 – 8.1|24 – 27|2016-2017|
|Pie – Android 10|9 – 10|28 – 29|2018-2019|
|Android 11 – 12L|11 – 12.1|30 – 32|2020-2022|
|Android 13 – 16|13 – 16 Beta|33 – 36|2022-2025|

**💡 Nota Pentest:**

- Ver la **versión exacta en dispositivo:** `Settings → About → Android Version`.
    
- Cada versión define la **API y compatibilidad de apps**, esencial para exploits y pruebas de seguridad.
    

---

## **4️⃣ Hardware soportado**

- **Arquitecturas:**
    
    - ARM (AArch64) → mayoría de smartphones
        
    - x86 / x86-64 → Intel, PCs con Android-x86
        
- **Sensores comunes:** cámara, GPS, acelerómetro, giroscopio, barómetro, magnetómetro, proximidad, presión, termómetro, touchscreen
    
- **Emulación:** Android Emulator y emuladores de terceros permiten pruebas en arquitecturas no nativas.
    

**💡 Nota Pentest:**

- La arquitectura y hardware afectan **exploits kernel y drivers**.
    
- Sensores y cámaras pueden ser vectores de ataque si las apps no gestionan correctamente los permisos.
    

---

## **5️⃣ Claves para un Pentester de Android**

1. **Entender el OS:** kernel Linux modificado, arquitectura, versiones, API levels.
    
2. **Distribución de apps:** tiendas oficiales vs. repositorios alternativos.
    
3. **Historial de versiones:** ayuda a identificar vulnerabilidades conocidas.
    
4. **Hardware y sensores:** influyen en técnicas de explotación y pruebas de seguridad.
    
5. **Emulación:** usar Android Studio AVD o proyectos como Android-x86 para pruebas controladas.
    

---

✅ **Resumen Visual**

```
Android OS
├─ Kernel: Linux modificado
├─ Distribución apps: GMS, Play, F-Droid, APKMirror…
├─ Dispositivos: phones, tablets, TV, wearables
├─ Versiones: 1.0 → 16 Beta, API 1 → 36
├─ Hardware: ARM, x86, sensores varios
├─ Pentest: versión, API, arquitectura, apps no oficiales
```
