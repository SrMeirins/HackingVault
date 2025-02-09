### **Blind SQL Injection: Extracción de credenciales mediante respuesta condicional**

Este método se basa en la técnica de **Blind SQL Injection por respuesta condicional**. No obtenemos directamente los datos inyectados, sino que inferimos información observando cambios en la respuesta de la aplicación. En este caso, la aplicación muestra o no el mensaje *"Welcome back!"* dependiendo de si la consulta SQL evaluada es verdadera o falsa.

---

#### **Contexto de la Inyección**

- **Cookie vulnerable:**  
  La cookie `TrackingId` se utiliza para mantener información de sesión o seguimiento.  
  Ejemplo inicial:  
  ```
  TrackingId=9SiQFkPaMB9h5csj
  ```
  
- **Efecto de la inyección:**  
  Al inyectar una comilla (`'`) y agregar condiciones lógicas, modificamos la consulta interna.  
  - **Ejemplo 1:**  
    ```
    TrackingId=9SiQFkPaMB9h5csj' and 1=2-- 
    ```  
    El `1=2` es falso, y la respuesta ya no muestra el mensaje *"Welcome back!"*.  
  - **Ejemplo 2:**  
    ```
    TrackingId=9SiQFkPaMB9h5csj' and 1=1-- 
    ```  
    El `1=1` es verdadero, y el mensaje *"Welcome back!"* se muestra normalmente.  

Estos cambios en la respuesta nos permiten utilizar condiciones lógicas para inferir información sobre la base de datos.

---

#### **Paso 1: Confirmar la Existencia de la Tabla "users"**

**Payload:**  
```
TrackingId=9SiQFkPaMB9h5csj' and (select 'x' from users limit 1)='x'--
```

- **Objetivo:**  
  Verificar si la tabla `users` existe en la base de datos.

- **Explicación detallada:**  
  - La parte inyectada se añade tras cerrar la cadena original:  
    ```
    ' and (select 'x' from users limit 1)='x'--
    ```  
  - Se ejecuta una subconsulta:  
    ```sql
    (select 'x' from users limit 1)
    ```  
    Esto intenta seleccionar el carácter `'x'` de la tabla `users` (limitando el resultado a una fila).  
  - Se compara el resultado de la subconsulta con la cadena `'x'`.  
    - **Si la tabla `users` existe y la consulta se ejecuta correctamente:**  
      La comparación es verdadera y la condición general se evalúa como verdadera, mostrando el mensaje *"Welcome back!"*.  
    - **Si la tabla no existe:**  
      La consulta fallará y, consecuentemente, el mensaje no se mostrará.

---

#### **Paso 2: Confirmar la Existencia del Usuario "administrator"**

**Payload:**  
```
TrackingId=9SiQFkPaMB9h5csj' and (select 'x' from users where username = 'administrator')='x'--
```

- **Objetivo:**  
  Verificar que existe un registro en la tabla `users` donde el campo `username` es igual a `'administrator'`.

- **Explicación detallada:**  
  - Se inyecta una subconsulta que intenta seleccionar `'x'` de la tabla `users` filtrando por el usuario `administrator`:  
    ```sql
    (select 'x' from users where username = 'administrator')
    ```  
  - La condición compara el resultado de la subconsulta con `'x'`.  
    - **Si el usuario `administrator` existe:**  
      La condición se cumple y se muestra el mensaje *"Welcome back!"*.  
    - **Si no existe:**  
      La subconsulta no devuelve resultados, la condición falla y el mensaje desaparece.

---

#### **Paso 3: Determinar la Longitud de la Contraseña**

**Payload (Ejemplo para verificar si la longitud es mayor que un valor específico):**  
```
TrackingId=9SiQFkPaMB9h5csj' and (select 'x' from users where username = 'administrator' and length(password)>1)='x'--
```

- **Objetivo:**  
  Determinar la longitud de la contraseña del usuario `administrator`.

- **Explicación detallada:**  
  - La subconsulta ahora añade una condición adicional:  
    ```sql
    where username = 'administrator' and length(password)>1
    ```  
  - Se utiliza la función `length(password)` para evaluar la longitud de la contraseña.  
  - Mediante un ataque de fuerza bruta (usando la herramienta BurpSuite en modo **Sniper**), se varía el valor numérico en la condición `length(password)>N` para encontrar el umbral a partir del cual el mensaje *"Welcome back!"* deja de aparecer.  
  - **Ejemplo de iteración:**  
    - Si `length(password)>19` devuelve *"Welcome back!"* pero `length(password)>20` no, se deduce que la contraseña tiene **20 caracteres**.

---

#### **Paso 4: Extraer la Contraseña Carácter por Carácter**

**Payload (Ejemplo para extraer el primer carácter):**  
```
TrackingId=9SiQFkPaMB9h5csj' and (select substring(password,1,1) from users where username = 'administrator')='a'--
```

- **Objetivo:**  
  Extraer cada carácter de la contraseña del usuario `administrator` de forma individual.

- **Explicación detallada:**  
  - La función `substring(password,1,1)` extrae el primer carácter del campo `password`.  
  - Se compara el resultado de la subconsulta con un carácter específico, en este caso `'a'`.  
  - **Proceso de extracción:**  
    - Se utiliza BurpSuite en modo **Intruder** con la opción **Cluster Bomb** para automatizar el proceso.  
    - Se configuran dos conjuntos de payloads:  
      1. **Posición del carácter:** Un valor numérico que indica la posición en la cadena (por ejemplo, 1 a 20).  
      2. **Carácter a comparar:** Un conjunto de posibles caracteres (por ejemplo, letras, números y símbolos).  
    - Para cada posición, se itera a través de los posibles caracteres.  
    - **Cuando la condición es verdadera (se muestra "Welcome back!")**, se ha encontrado el carácter correcto para esa posición de la contraseña.  
    - El proceso se repite para cada una de las posiciones hasta reconstruir la contraseña completa.

---

### **Resumen del Proceso**

1. **Verificar la vulnerabilidad:**  
   Comprobamos que la inyección funciona utilizando condiciones lógicas simples (`1=1` y `1=2`).

2. **Confirmar la existencia de la tabla y usuario:**  
   - Verificamos que la tabla `users` existe.
   - Confirmamos que el usuario `administrator` está presente en la tabla.

3. **Determinar la longitud de la contraseña:**  
   Utilizamos una condición que comprueba si la longitud de la contraseña es mayor que un valor y ajustamos este valor hasta determinar la longitud exacta.

4. **Extraer la contraseña carácter por carácter:**  
   Se itera sobre cada posición del campo `password`, probando posibles caracteres y validando la respuesta condicional para reconstruir la contraseña completa.

Estos pasos, cuando se combinan con herramientas automatizadas como BurpSuite (usando los modos **Sniper** y **Cluster Bomb**), permiten extraer información sensible de la base de datos a pesar de que no se muestre directamente el resultado de la consulta.

---

Este método de **Blind SQL Injection por respuesta condicional** es especialmente útil cuando la aplicación no muestra errores o resultados directos de la consulta, permitiendo a un atacante inferir datos críticos a través de cambios sutiles en el comportamiento de la aplicación.
