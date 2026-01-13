Android es un sistema complejo, con múltiples capas de seguridad que protegen tanto el dispositivo como los datos de las aplicaciones. Entender estas características es crucial para cualquier análisis de seguridad o pentesting en Android.

---

## **1. Lenguajes de Desarrollo y APKs**

Las aplicaciones Android se desarrollan principalmente en **Kotlin** o **Java**, y se compilan con el **Android SDK** en un **APK (Android Package)**.

**Un APK contiene:**

- Código compilado en bytecode (.dex)
    
- Archivo manifest con metadatos
    
- Recursos (imágenes, layouts, strings)
    
- Librerías nativas (.so)
    
- Firmas digitales
    

### ⚠ Importancia de la compilación

- Toda app corre **dentro de un sandbox** propio.
    
- Cada componente y librería hereda el modelo de seguridad del kernel Linux.
    
- Modificar un APK sin respetar la firma puede comprometer la integridad del sistema.
    

---

## **2. Sandbox de Aplicaciones**

Android implementa un **sandbox a nivel kernel**:

- Cada app recibe un **UID único**.
    
- Se ejecuta en **su propio proceso**, con su propia instancia de ART.
    
- El sistema gestiona **inicio y cierre automático** de procesos según demanda.
    
- Aplica el principio de **least privilege**: la app solo tiene los permisos estrictamente necesarios.
    

### ⚡ Detalles importantes

- Las apps **no pueden acceder a datos de otras apps** sin permisos explícitos.
    
- La sandbox protege tanto código nativo como bytecode.
    
- Escapar del sandbox requiere **explotar vulnerabilidades del kernel**.
    

### 🔍 Ejemplo práctico

```bash
root:/# ls -l /data/data/
drwx------  4 u0_a114  u0_a114  4096  com.android.chrome
drwx------  5 u0_a119  u0_a119  4096  com.android.camera2
```

- Cada app tiene **propietario único** → aislamiento efectivo.

---

## **3. Protecciones Adicionales**

Android introduce varias capas más allá del UID:

| Protección                             | Función                                            |
| -------------------------------------- | -------------------------------------------------- |
| SELinux Mandatory Access Control (MAC) | Aísla apps del sistema                             |
| SELinux sandbox                        | Aísla apps entre usuarios físicos                  |
| Seccomp-BPF                            | Limita syscalls que la app puede usar              |
| SELinux + MAC para apps targetSdk ≥ 28 | Protección extendida para apps modernas            |
| Vista limitada del sistema de archivos | Apps no pueden acceder a /sdcard/DCIM directamente |

**Notas de seguridad:**

- Compartir archivos entre apps requiere implementación segura.
    
- Desde targetSdk ≥ 28, **ya no se permite el acceso “world-readable”** → reduce riesgo de filtraciones.
    

---

## **4. Firma de Aplicaciones (APK Signing)**

Para instalar o distribuir una app:

1. El APK debe estar **firmado digitalmente**.
    
2. Protege contra **modificaciones maliciosas**.
    
3. Existen diferentes **signature schemes**:
    

|Esquema|Introducción|Comentario|
|---|---|---|
|v1 (JAR Signing)|Android ≤ 7|Vulnerable a Janus (inyección de DEX)|
|v2|Android 7+|Mejora integridad de APK completo|
|v3|Android 9+|Añade metadatos adicionales|
|v4|Android 11+|Merkle hash tree, requiere v2/v3 para compatibilidad|
![[Pasted image 20251117172052.png]]
### ⚡ Vulnerabilidad Janus (CVE-2017-13156)

- Solo afecta APKs firmados con v1.
    
- Permite **inyectar DEX maliciosos** sin romper la firma.
    
- Puede ejecutarse en Android 5.0 < 8.1.
    

### ⚡ Cómo firmar un APK

1. Generar clave:
    

```bash
keytool -genkey -keystore key.keystore -alias john
```

2. Optimizar con `zipalign`:
    

```bash
zipalign -p -f -v 4 myapp.apk myapp_signed.apk
```

3. Firmar con `apksigner`:
    

```bash
apksigner sign --ks key.keystore myapp_signed.apk
```

**Resultado:** APK protegido, listo para instalación o Play Store.

---

## **5. Verified Boot**

Android utiliza **Verified Boot** para asegurar la integridad del sistema operativo:

- Cada etapa de arranque verifica la siguiente usando **claves criptográficas**.
    
- Garantiza que solo el software autorizado pueda ejecutarse.
    
- Incluye **Rollback Protection** para evitar volver a versiones vulnerables.
    
- Dispositivos no verificados alertan al usuario o no arrancan.
    

### ⚡ Flujo de boot seguro

1. Verificar bloqueo del dispositivo.
    
2. Validar la integridad del root filesystem.
    
3. Si es válido → arranca sistema.
    
4. Si no → alerta o bloquea el arranque.
    

**Importancia en pentesting:**

- Rootkits o malware necesitan **romper Verified Boot** para persistir.
    
- La verificación asegura que los exploits no sean persistentes después de reinicio.
    

---

## **6. Conclusiones Clave de Seguridad Android**

1. **Sandboxing fuerte**: aislamiento de apps y procesos.
    
2. **UID y permisos Linux**: base del control de acceso.
    
3. **SELinux + MAC**: defensa adicional para apps modernas.
    
4. **Firma de APK**: integridad de aplicaciones y mitigación de inyecciones.
    
5. **Verified Boot**: protege contra modificaciones de SO y persistencia de malware.
    
6. **Principio de least privilege**: apps solo acceden a recursos necesarios.
    

**Para pentesting y análisis de seguridad:**

- Verificar permisos y sandboxing de apps.
    
- Revisar versiones de signature schemes.
    
- Analizar posibles bypass de Verified Boot.
    
- Auditar SELinux y políticas de MAC.
    
- Comprobar accesos a filesystem y seguridad de almacenamiento compartido.