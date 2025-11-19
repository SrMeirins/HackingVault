
# **1. Introducción General a Android**

Android es un sistema operativo móvil basado en **Linux**, diseñado para proporcionar:

- Un ambiente seguro.
    
- Una experiencia consistente entre dispositivos.
    
- Un ecosistema flexible para fabricantes y desarrolladores.
    
- Un entorno aislado que protege al usuario y sus datos.
    

Desde el punto de vista de pentesting, Android es especialmente interesante porque:

- Es **el SO móvil más utilizado del mundo** → mayor superficie de ataque.
    
- Está formado por muchas capas, cada una con posibles vectores.
    
- Combina **Linux**, **Java/Kotlin**, **C/C++**, **APIs de sistema**, **HAL**, **drivers**, etc.
    

**Comprender su arquitectura es esencial para:**

- Detectar vulnerabilidades de apps.
    
- Analizar comportamientos sospechosos.
    
- Hacer reversing e instrumentación.
    
- Explorar fallos en la comunicación entre capas.
    
- Evaluar seguridad del dispositivo y del firmware.
    

---

# 🟦 **2. El Shell de Android: Acceso al Sistema**

Android incluye una **shell Linux**, accesible mediante:

- ADB (Android Debug Bridge)
    
- Terminales instaladas en el dispositivo
    
- Emuladores
    

Cuando abres una shell, interactúas **directamente con el sistema operativo**, los permisos del usuario y el kernel.

### Ejemplo real:

```bash
emu64x:/sdcard # ls -l
```

Salida típica:

- Directorios como `DCIM`, `Pictures`, `Download`, `Android`
    
- Propietarios como `u0_a143`
    
- Grupos como `media_rw`
    

### ¿Por qué es importante en seguridad?

- Muestra qué datos están expuestos sin necesidad de root.
    
- Permite verificar permisos de lectura/escritura de apps.
    
- Permite acceder a logs, inspeccionar procesos, mover ficheros, etc.
    
- Es el punto de partida para _explotación local_.
    

---

# 🟦 **3. Arquitectura General (Software Stack)**

La arquitectura de Android está organizada en **capas verticales** donde cada nivel solo interactúa con el inmediatamente superior o inferior.  
Esto es clave para entender tanto la seguridad como los vectores de ataque.

```
┌──────────────────────────┐
│       System Apps        │
├──────────────────────────┤
│     Java API Framework   │
├──────────────────────────┤
│  Native C/C++ Libraries  │
├──────────────────────────┤
│ Android Runtime (ART)    │
├──────────────────────────┤
│          HAL             │
├──────────────────────────┤
│       Linux Kernel       │
└──────────────────────────┘
```

---

# 🟦 **4. Linux Kernel (La Base del Sistema)**

## 4.1 ¿Qué es el Kernel?

El kernel es la **capa más profunda** del sistema.  
Es el encargado de:

- Controlar y comunicarse con el hardware.
    
- Gestionar procesos.
    
- Gestionar memoria.
    
- Realizar control de accesos.
    
- Mantener la seguridad a nivel núcleo.
    

Android usa un kernel Linux **modificado** con características específicas:

- **Wakelocks** (control de energía)
    
- **Binder IPC**
    
- **Android-specific drivers**
    
- **Security patches propios**
    

## 4.2 Funciones técnicas importantes

### 🔹 _Gestión de procesos (Scheduler)_

Determina qué proceso se ejecuta y cuándo.

### 🔹 _Gestión de memoria (MMU)_

Cada app tiene su propio espacio de memoria → sandboxing.

### 🔹 _Drivers_

Permiten interactuar con:

- Cámara
    
- WiFi
    
- Bluetooth
    
- Sensor de proximidad
    
- Touchscreen
    
- GPS
    

### 🔹 _Seguridad de kernel_

Incluye:

- Control de capacidades Linux (capabilities)
    
- Namespaces
    
- Cgroups
    
- Mecanismos de aislamiento
    
- SELinux (en modo enforcing desde Android 5+)
    

## 4.3 Relevancia para pentesting

- Vulnerabilidades del kernel permiten **escalada a root**.
    
- Control del kernel implica control del dispositivo completo.
    
- Malware avanzado intenta evadir SELinux o inyectar código a drivers.
    

---

# 🟦 **5. Hardware Abstraction Layer (HAL)**

## 5.1 ¿Qué es HAL?

El **Hardware Abstraction Layer** es una colección de **interfaces definidas por Android** que los fabricantes implementan para su hardware.

Es decir:

> HAL convierte el hardware real en una API estandarizada que Android puede usar.

## 5.2 ¿Por qué existe?

Porque cada fabricante tiene hardware distinto. Sin HAL:

- Sería imposible que Android fuese un sistema multiplataforma.
    
- Habría que reescribir Android para cada dispositivo.
    

## 5.3 ¿Cómo funciona?

- El framework llama a un método (por ejemplo, “encender cámara”).
    
- El framework envía esto al HAL correspondiente.
    
- HAL transforma la instrucción en llamadas al hardware real.
    

HAL está implementado en librerías compartidas:

```
/system/lib/hw/
```

Por ejemplo:

```
camera.default.so
gps.default.so
audio.primary.msm8937.so
```

## 5.4 Relevancia en pentest

- Un bug en una HAL puede comprometer cámaras, audio, GPS, etc.
    
- Existen exploits de drivers de cámara, WiFi o GPU.
    
- HAL es uno de los puntos donde malware avanzado se oculta.
    

---

# 🟦 **6. Android Runtime (ART)**

## 6.1 ART: el motor de ejecución de apps

ART ejecuta el bytecode DEX de Android.

Antes de Android 5.0 existía **Dalvik VM**, pero fue reemplazado por ART.

## 6.2 Cómo ejecuta ART las apps

ART mejora la ejecución de apps usando **AOT (Ahead-Of-Time)**:

- Cuando instalas una app, se compila a código nativo.
    
- El código nativo se almacena en el dispositivo.
    
- Las apps arrancan más rápido y consumen menos CPU.
    

Pero desde Android 7, ART es **híbrido**:

- Compila AOT.
    
- Usa JIT (Just-In-Time) si hace falta.
    
- Usa perfiles PGO para optimización inteligente.
    

## 6.3 ¿Qué es DEX?

DEX (_Dalvik Executable_) es el formato de bytecode de Android.

Se genera a partir de código Java/Kotlin o C++ (si se usa JNI).

## 6.4 Relevancia para pentesting

- El análisis estático (apktool, jadx, bytecode viewer) permite ver código DEX.
    
- ART facilita el reversing de apps.
    
- Muchas apps intentan ocultar lógica nativa en librerías C++ (NDK).
    

---

# 🟦 **7. Native Libraries (C/C++ Libraries)**

## 7.1 ¿Qué son?

Android incorpora una gran colección de librerías nativas:

- libc
    
- libm
    
- OpenGL ES
    
- libmedia
    
- libcamera
    
- WebKit/WebView components
    
- Bionic (la libc de Android)
    

## 7.2 Usos principales

- Código de alto rendimiento.
    
- Interacción directa con hardware.
    
- Procesamiento multimedia.
    
- Criptografía.
    
- Motores 3D y videojuegos.
    

## 7.3 Relevancia en pentesting

- Las librerías nativas pueden contener vulnerabilidades clásicas:
    
    - Buffer overflows
        
    - Desbordamientos de heap/stack
        
    - Use-after-free
        
- Muchas apps de banca ocultan código sensible en NDK.
    

---

# 🟦 **8. Java API Framework**

## 8.1 Función general

Aquí reside la **lógica del sistema operativo**, basada en clases Java/Kotlin.

Incluye:

- Activity Manager
    
- Window Manager
    
- Notification Manager
    
- Location Manager
    
- Telephony Manager
    
- Package Manager
    
- Content Providers
    

## 8.2 ¿Por qué es importante?

Porque todas las apps se comunican con Android mediante estas APIs.

Ejemplo:

Cuando una app quiere acceder a la ubicación:

1. Llama a LocationManager.
    
2. LocationManager valida permisos.
    
3. LocationManager intercambia datos con HAL (GPS).
    
4. HAL comunica con hardware.
    

## 8.3 Relevancia para pentesting

- Permite identificar abuso de APIs.
    
- Permite detectar apps que piden permisos excesivos.
    
- Permite detectar riesgos en Content Providers (filtraciones de datos).
    
- Permite analizar vectores de Inter-Process Communication (intent hijacking).
    

---

# 🟦 **9. System Apps (Aplicaciones del Sistema)**

Las apps preinstaladas incluyen:

- Cámara
    
- Contactos
    
- Teléfono
    
- Mensajes
    
- Calendario
    
- Ajustes
    
- Navegador
    

## 9.1 ¿Qué tienen de especial?

- Pueden tener permisos “signature-level”.
    
- Pueden acceder a APIs restringidas.
    
- A veces contienen vulnerabilidades por falta de actualizaciones.
    

## 9.2 Relevancia para pentesting

- Un bug en una app del sistema puede comprometer el dispositivo completo.
    
- Muchas ROMs personalizadas traen apps inseguras.
    
- OEM apps son un vector común de ataque.
