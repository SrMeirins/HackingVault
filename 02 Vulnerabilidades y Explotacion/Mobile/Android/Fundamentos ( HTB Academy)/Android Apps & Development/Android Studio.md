Android Studio es el **IDE oficial de Android**, basado en IntelliJ IDEA y mantenido por Google. Para un pentester, entender cómo funciona el entorno de desarrollo es fundamental porque:

- Permite comprender cómo se estructura internamente una app.
    
- Facilita identificar rutas, ficheros y configuraciones habituales.
    
- Ayuda a reconstruir APKs, interpretar el código revertido y entender la lógica de build.
    
- Permite generar entornos controlados para pruebas dinámicas.
    

Aunque Android Studio está pensado para desarrollo, **es una herramienta clave para ingeniería inversa**, debugging, emulación y análisis.

---

# 📥 1) Instalación en Linux (Debian/Ubuntu)

En Linux no existe un instalador gráfico: descargas el paquete `.tar.gz`, lo descomprimes y ejecutas el script del IDE.

```bash
wget https://redirector.gvt1.com/edgedl/android/studio/ide-zips/2024.3.1.14/android-studio-2024.3.1.14-linux.tar.gz
tar xvzf android-studio-2024.3.1.14-linux.tar.gz
sh android-studio/bin/studio.sh

# Ajustar la versión
```

### Setup Wizard:

1. **Next** varias veces
    
2. Aceptar **SDK License**
    
3. Dejar que se descarguen componentes (SDK, plataforma, herramientas)
    
4. Pulsar **Finish**
    

Luego → _New Project_ → _Empty Views Activity_ → Lenguaje Java → Finalizar.

📌 **Nota:** Para pentesting, instalar **Android SDK Platform Tools** y **AVD Manager** es necesario para emular dispositivos y usar ADB.

---

# 📂 2) Estructura del Proyecto en Android Studio

Comprender cómo ve Android Studio un proyecto ayuda a mapearlo mentalmente al decompilar un APK. Cada carpeta tiene un propósito específico y se refleja (casi directamente) en el contenido final del APK.

---

## **📁 app/** — módulo principal

Dentro está la lógica y recursos que finalmente producirán un APK. Android Studio divide esta carpeta en:

### ✔ **`manifests/`**

Incluye:

- `AndroidManifest.xml`
    
- Configuraciones adicionales como `NetworkSecurityConfig`
    

📍 _Relevancia de seguridad:_  
Aquí se define **todo lo exportado**, permisos, deep links, niveles de SDK, configuración de red, etc.

---

### ✔ **`java/`**

Contiene el código fuente del proyecto:

```
app/src/main/java/com/ejemplo/myapp/MainActivity.java
```

Incluye:

- Activities
    
- Services
    
- Broadcast Receivers
    
- Content Providers
    
- Controladores de UI
    
- Lógica de negocio
    

📍 _En análisis de APKs:_  
Esto corresponde directamente a **classes.dex**, que revertiremos con JADX o apktool.

---

### ✔ **`res/`**

Recursos estáticos que NO son modificables en runtime:

- `layout/` (interfaces XML)
    
- `values/` (strings, estilos, colores)
    
- `drawable/` (imágenes vectoriales/PNG)
    
- `xml/` (configuraciones, seguridad, providers)
    
- `raw/` (ficheros sueltos accesibles en `R.raw`)
    

📍 _En el APK se convierte en:_  
`res/` + `resources.arsc`

---

# 📜 3) Gradle Scripts (bases del sistema de compilación)

Android Studio usa **Gradle**, un sistema de build altamente configurable.  
Los scripts más relevantes:

### ✔ **`build.gradle`**

Controla:

- Dependencias
    
- Build types (`debug`, `release`)
    
- Ofuscación/optimización (ProGuard / R8)
    
- Firma de la app
    
- Productos múltiples (flavors)
    

### ✔ **`proguard-rules.pro`**

Reglas personalizadas para:

- Ofuscar nombres de clases/métodos
    
- Mantener clases necesarias para reflección
    
- Minimizar código
    

📍 _En pentesting:_

- Si la app tiene R8/ProGuard activo → decompilación más difícil.
    
- Revisar qué clases están excluidas de ofuscación.
    
- Ver qué librerías externas usa (OAuth, crypto, trackers…).
    

📎 **Dato importante:**  
Una sola base de código puede generar **múltiples APKs** (release, debug, flavors, ABI-split).

---

# 📱 4) Tipos de Aplicaciones (Nat/Híbridas/Web)

Esto es esencial para un pentester: determina la superficie de ataque.

---

## 🟩 **1) Native Apps (Java/Kotlin)**

Características:

- Acceden directamente a APIs del sistema.
    
- Mejor rendimiento y seguridad.
    
- Código final → `classes.dex` / `.so`.
    

Ventajas de seguridad:

- Integración con permisos Android.
    
- Difíciles de manipular (aunque no imposible).
    
- Mejor soporte para seguridad (Keystore, biometría…).
    

---

## 🟨 **2) Web Apps (PWA, apps web puras)**

Hechas con:

- HTML
    
- CSS
    
- JavaScript
    

No hay APK, el navegador ejecuta la lógica. Vulnerabilidades típicas:

- **XSS**, **CSRF**, **CSP débil**
    
- Tráfico sin cifrar
    
- Exposición de APIs web
    

---

## 🟧 **3) Hybrid Apps (Cordova, Ionic, React Native, Flutter)**

Combinan:

- Contenedor nativo
    
- WebView interno
    
- Lógica JS o Dart empaquetada en assets
    

Debilidades comunes:

- XSS dentro del WebView
    
- JavaScript bridges inseguros (`addJavascriptInterface`)
    
- Configuraciones inseguras de WebView
    
- Cert pinning incorrecto
    
- Assets con código expuesto (`www/`, bundles JS)
    

Identificación:

- Carpeta `assets/www/` (Cordova)
    
- Carpeta `lib/<ABI>/libflutter.so` (Flutter)
    
- Archivos JS pesados en `assets/`
    

---

# 🧠 Conclusión

Android Studio no es solo un IDE:  
Es **la plantilla base que da forma al APK**, así que entender su estructura te permite:

- Reconstruir apps tras descompilarlas
    
- Identificar puntos débiles en el diseño
    
- Reconocer frameworks y tipos de app
    
- Interpretar rutas, dependencias, servicios y componentes exportados
    
- Analizar cómo se genera el APK y cómo se firma/ofusca