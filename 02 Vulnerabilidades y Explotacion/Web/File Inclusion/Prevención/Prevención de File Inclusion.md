Es fundamental aprender **cómo proteger nuestras aplicaciones y servidores** para minimizar riesgos y limitar el impacto si un fallo ocurre.

---

## 1️⃣ **Evitar pasar entradas de usuario a funciones de inclusión**

El principio más importante es **no permitir que ninguna entrada del usuario llegue directamente a funciones que incluyan archivos**. Por ejemplo, funciones de PHP como:

- `include()`, `include_once()`
    
- `require()`, `require_once()`
    
- `file_get_contents()`
    

En NodeJS, Java o .NET también existen funciones equivalentes que leen o incluyen contenido.

**Buenas prácticas:**

- Cargar dinámicamente recursos **sin intervención del usuario**.
    
- Si no se puede evitar, usar **listas blancas** (whitelists) para validar cada entrada.
    
- Ejemplos de whitelist:
    
    - **Base de datos** que relacione IDs con archivos permitidos.
        
    - **Script de mapeo** que traduzca nombres a archivos concretos.
        
    - **JSON estático** que relacione nombres con rutas.
        

✅ Con esto, aunque el usuario envíe un parámetro malicioso, solo se cargará un archivo permitido.

---

## 2️⃣ **Prevención de Directory Traversal**

El **directory traversal** permite escapar del directorio web y acceder a archivos sensibles, como:

- `/etc/passwd` → usuarios válidos o claves SSH.
    
- Archivos de servicios como `tomcat-users.xml`.
    
- Cookies de sesión PHP → secuestro de sesiones.
    
- Código fuente y configuraciones de la aplicación web.
    

**Cómo prevenirlo:**

- Usar funciones nativas del lenguaje para aislar el **nombre del archivo**.  
    Por ejemplo en PHP:
    

```php
$filename = basename($input); // devuelve solo el nombre del archivo
```

⚠️ Limitación: Si la aplicación necesita entrar a subdirectorios, basename() puede bloquearlo.

- **Sanitizar entradas del usuario**, eliminando patrones de escape como `../`:
    

```php
while(substr_count($input, '../')) {
    $input = str_replace('../', '', $input);
}
```

- **Evitar crear funciones propias para sanitización** que puedan ignorar casos especiales (`.?`, `*`) que podrían ser interpretados de manera distinta en el sistema y en PHP.
    

---

## 3️⃣ **Configuración del Servidor Web**

Algunas configuraciones globales pueden reducir el impacto de LFI:

- Deshabilitar **inclusión de archivos remotos**:
    
```php
allow_url_fopen = Off
allow_url_include = Off
```
    
- Limitar la aplicación al **directorio raíz web**:
    
    - Con PHP: `open_basedir = /var/www`
        
    - Alternativa moderna: ejecutar la app en **Docker** para aislarla.
        
- Deshabilitar módulos peligrosos como `PHP Expect` o `mod_userdir`.
    

Con estas medidas, aunque se detecte LFI, **el atacante no podrá leer archivos fuera del directorio web**.

---

## 4️⃣ **Uso de WAF (Web Application Firewall)**

Un **WAF** como **ModSecurity** añade una capa extra de protección:

- Permite **bloquear o alertar** sobre intentos de inclusión de archivos.
    
- El modo recomendado es **permisivo**, para **reportar ataques sin bloquear tráfico legítimo**.
    
- Proporciona **alertas tempranas** y ayuda a detectar ataques antes de que tengan impacto.
    

💡 Según el **FireEye M-Trends Report 2020**, las compañías tardaban **30 días de media** en detectar intrusiones. Un WAF y buen hardening ayudan a **identificar ataques rápidamente** mediante logs detallados.

---

## 5️⃣ **Objetivo del Hardening**

- No existe un sistema **100% invulnerable**.
    
- El hardening debe:
    
    - Aumentar la **resiliencia** de la aplicación.
        
    - Generar **logs claros y detallados** para identificar intentos de ataque.
        
    - Mantenerse actualizado y **revisarse tras cada zero-day** relevante (ej: Apache Struts, Rails, Django).
        

⚠️ Un sistema “duro” no reemplaza el monitoreo. Los logs y auditorías continuas son esenciales.

---

### ✅ **Resumen práctico de prevención**

|Riesgo|Prevención recomendada|
|---|---|
|Inclusión de archivos (LFI)|No pasar input del usuario a `include()`. Usar whitelist.|
|Directory traversal|Usar `basename()`, sanitizar `../`, evitar funciones caseras.|
|Archivos fuera de webroot|Configurar `open_basedir` o aislar con Docker.|
|Archivos remotos|`allow_url_include = Off`, `allow_url_fopen = Off`.|
|Ataques automáticos|WAF en modo permisivo y monitoreo de logs.|
