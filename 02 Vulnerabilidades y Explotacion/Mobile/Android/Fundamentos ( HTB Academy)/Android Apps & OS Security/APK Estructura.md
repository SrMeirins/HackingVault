Un **APK (Android Package)** es el archivo que contiene todo lo necesario para instalar y ejecutar una aplicación Android. Técnicamente es un **ZIP** con una estructura y archivos concretos: código compilado, recursos, manifiesto, librerías nativas y metadatos de firma.

---

## 🔎 ¿Qué contiene un APK? (visión general)

```
myapp.apk  (ZIP)
├─ AndroidManifest.xml     # Metadatos y componentes
├─ META-INF/               # Firma y certificados
├─ classes.dex             # Código compilado (DEX)
├─ classes2.dex, ...       # (multidex si existe)
├─ lib/                    # Librerías nativas (.so) por ABI
│   ├─ arm64-v8a/
│   ├─ armeabi-v7a/
│   ├─ x86/
│   └─ x86_64/
├─ res/                    # Recursos (XML, drawables…)
├─ assets/                 # Archivos crudos accesibles vía AssetManager
└─ resources.arsc          # Índice binario de recursos
```

Comando básico para inspeccionar:

```bash
unzip -l myapp.apk
```

---

## 1) `AndroidManifest.xml` — el mapa de la app

**Contenido clave:**

- `package` (nombre único)
    
- `minSdkVersion`, `targetSdkVersion`
    
- `components`: `<activity>`, `<service>`, `<provider>`, `<receiver>`
    
- `permissions` solicitadas (dangerous / normal / signature)
    
- `intent-filters` (Deep links, implicit intents)
    
- `networkSecurityConfig` (configuración TLS / certificados)
    
- `uses-permission` / `uses-feature`
    

**Por qué importa en pentesting:**

- Revisa permisos excesivos (p.ej. `READ_SMS`, `SEND_SMS`, `READ_CONTACTS`).
    
- `exported="true"` en componentes sensibles → posible _component hijacking_.
    
- `ContentProvider` mal protegido → _data leakage_.
    
- `networkSecurityConfig` mal configurado permite MITM (certificados user-added, cleartext).
    

**Herramientas para leerlo (legible):**

```bash
aapt dump badging myapp.apk
apktool d myapp.apk   # produce AndroidManifest.xml legible (decodifica resources)
jadx-gui myapp.apk    # muestra manifiesto y código
```

---

## 2) `classes.dex` / DEX / Multidex

**Qué es:**

- Contiene bytecode DEX generado a partir de Java/Kotlin.
    
- Android Runtime (ART) o Dalvik interpreta/ejecuta DEX.
    
- Apps grandes usan _multidex_: `classes2.dex`, `classes3.dex`, ...
    

**Análisis:**

- Decompilar con `jadx` o `dex2jar + jd-gui`.
    
- Ver strings sensibles (`grep -a "password" classes.dex`), endpoints, claves hardcoded.
    
- Detectar ofuscación (nombres crípticos, strings encriptadas).
    

**Técnicas ofensivas comunes:**

- Repackaging: modificar classes.dex para añadir payload.
    
- Hooking dinámico (Frida) apuntando a métodos DEX.
    
- Inyección de código si APK firmado con v1 (ver Janus).
    

---

## 3) `META-INF/` — firmas y certificados

**Archivos habituales:**

- `MANIFEST.MF` — hashes de ficheros.
    
- `CERT.SF` — firmas sobre MANIFEST entries.
    
- `CERT.RSA` (o `.DSA`) — certificado público + firma.
    

**Signature schemes:**

- **v1 (JAR signing)** — respalda entradas individuales (vulnerable a Janus).
    
- **v2 / v3** — firman el APK completo; protegen contra modificaciones internas.
    
- **v4** — Merkle tree (Android 11+), requiere v2/v3.
    

**Comprobación:**

```bash
apksigner verify --print-certs myapp.apk
```

**Riesgos / vectores:**

- APKs firmados únicamente con **v1** → riesgo CVE-2017-13156 _Janus_ (inyección DEX).
    
- Clave de firma reutilizada entre apps (riesgo de _signing confusion_).
    
- Repackaging: modificar el APK y resignarlo con otra clave → _trojanized apps_ (si usuario instala).
    

---

## 4) `res/` y `resources.arsc` — recursos

**`res/`** contiene layouts XML, drawables, strings, valores por idiomas o densidades de pantalla.  
**`resources.arsc`** es el índice binario que mapea `R.*` a recursos concretos.

**Pentest checklist:**

- Buscar `hardcoded` URLs en layouts o strings.
    
- Revisar `network_security_config` en `res/xml/` (trust-anchors, cleartextTrafficPermitted).
    
- Manipulación de layouts para _phishing overlays_ en ataques locales.
    
- Resource obfuscation vs strings en claro.
    

**Decodificar:**

```bash
apktool d myapp.apk   # extrae res/ y resources.arsc decodificado
```

---

## 5) `assets/` — archivos crudos

- Accesible vía `AssetManager`.
    
- Usado por frameworks híbridos (Cordova, React Native), juegos (archivos de recursos) y librerías.
    
- Puede contener código empaquetado (p. ej. frameworks JS, DLLs), bases de datos, certificados, o bundles.
    

**Pentest:** extrae y analiza (DBs, JS, config). Buscar secretos en assets.

---

## 6) `lib/` — librerías nativas (.so)

**Organización por ABI:** `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`.

**Importancia:**

- Código NDK (C/C++) puede contener vulnerabilidades nativas clásicas (buffer overflow, use-after-free).
    
- Funciones nativas son llamadas desde Java mediante **JNI** → revisar interfaz JNI para validar inputs.
    

**Análisis:**

- Extraer .so y usar `strings`, `readelf`, `objdump`, `Ghidra` o `IDA`.
    
- Buscar funciones criptográficas implementadas manualmente (riesgo de errores).
    
- Revisar símbolos exportados que permitan hooking o ejecución de payloads.
    

---

## 7) `resources.arsc` — mapa binario

- Mapea recursos y proporciona referencias compactas.
    
- APKTool lo decodifica a XML legible.
    
- Alterarlo sin respetar firma invalidará APK (si firma v2/v3).
    

---

## 8) Otros ficheros y carpetas importantes

- `kotlin/` — metadata de Kotlin, información de clases y reflection.
    
- `META-INF/` — verificado arriba (firma).
    
- `AndroidManifest.xml` binario (cuando se abre raw, parece ilegible; apktool lo convierte).
    

---

## 🔧 Herramientas esenciales para analizar APKs

- `unzip` / `jar` — listar contenido.
    
- `apktool` — decodificar recursos y manifest, reconstruir apk.
    
- `jadx` / `jadx-gui` — descompilar DEX a Java legible.
    
- `dex2jar` + `jd-gui` — alternativa para descompilar.
    
- `apksigner` / `jarsigner` — verificar o firmar APKs.
    
- `aapt` / `aapt2` — inspeccionar paquetes y recursos (`aapt dump xmltree`, `aapt dump badging`).
    
- `zipalign` — optimizar APK.
    
- `baksmali/smali` — desensamblar/ensamblar DEX (bytecode).
    
- `Ghidra/IDA/objdump` — analizar librerías nativas (.so).
    

Ejemplos:

```bash
aapt dump badging myapp.apk
apktool d myapp.apk -o myapp_decoded
jadx-gui myapp.apk
apksigner verify --print-certs myapp.apk
```

---

## ⚠ Vectores de ataque y riesgos asociados a la estructura del APK

1. **Repackaging & Trojans**
    
    - Modificar `classes.dex` o añadir payload, resignar y distribuir.
        
    - Defender: usar v2/v3 signatures, Play Protect, verificación de integridad.
        
2. **Janus (CVE-2017-13156)**
    
    - Inyección de DEX en APKs firmados solo con v1.
        
    - Defender: usar v2/v3, mantener targetSdk/compileSdk actualizados.
        
3. **Hardcoded secrets & endpoints**
    
    - Buscar en `classes.dex`, `assets/`, `res/values/strings.xml`.
        
    - Defender: usar keystores, no hardcodear, ofuscar + runtime secret injection.
        
4. **Native code exploits**
    
    - Vulnerabilidades en `.so` → escalada de privilegios o ejecución nativa.
        
    - Defender: ASLR, stack canaries, PIE, recompilación con flags de hardening.
        
5. **Misconfigured manifest**
    
    - `exported=true` en `ContentProvider` o `Activity` sensible → hijacking.
        
    - Defender: revisar `exported`, permisos `signature` y validaciones internas.
        
6. **Network/Security misconfig**
    
    - `networkSecurityConfig` permite certificados de usuario → MITM.
        
    - Defender: pinning de certificados, restringir trust anchors.
        
7. **Obfuscation bypass**
    
    - Ofuscadores protegen, pero strings todavía pueden filtrarse; análisis dinámico (Frida) suele sortear ofuscación.
        

---

## ✅ Buenas prácticas de desarrollador (que facilitan seguridad)

- Firmar con v2/v3/v4 y proteger la key de firma.
    
- No incluir secretos en código o assets; usar Android Keystore o servidores remotos.
    
- Fijar `targetSdkVersion` alto y cumplir políticas de permisos (scoped storage).
    
- Usar network security config correctamente (deny cleartext, cert pinning si procede).
    
- Minimizar `exported` en componentes; proteger `ContentProviders`.
    
- Harden native libs (PIE, RELRO, stack canaries, ASLR).
    

---

## 🧭 Flujo de auditoría rápida de un APK (checklist)

1. `unzip` + `apktool d` → inspeccionar `AndroidManifest.xml` y `res/`.
    
2. `aapt dump badging` → ver permisos, min/targetSdk, activities exportadas.
    
3. `jadx` → buscar strings sensibles, endpoints, lógica crítica.
    
4. `apksigner verify` → comprobar signature scheme.
    
5. Extraer `.so` → `readelf` / `strings` / `Ghidra`.
    
6. Revisar `network_security_config` y `assets/`.
    
7. Intentar repackage: modificar un fichero no protegido → resignar → test install (si firma débil).