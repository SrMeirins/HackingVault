# **Fuerza Bruta de Subdominios con `dnsenum` y `gobuster`**

Cuando una transferencia de zona (AXFR) falla, el siguiente paso es realizar un ataque de fuerza bruta para descubrir subdominios válidos. Para ello se utilizan herramientas que prueban una lista de nombres comunes (diccionario) contra el servidor DNS para ver cuáles de ellos existen.

## 1\. Enumeración con `dnsenum`

`dnsenum` es una herramienta muy completa que no solo realiza fuerza bruta, sino que también intenta obtener otra información útil del dominio (como registros MX, NS, etc.). Es una excelente primera opción para la enumeración activa.

### Comando

```bash
dnsenum --dnsserver <IP_Servidor_DNS> --threads 50 -f <ruta_diccionario> <dominio>
```

  * `--dnsserver`: Especifica el servidor DNS que queremos consultar.
  * `--threads`: Acelera la búsqueda ejecutando múltiples peticiones en paralelo.
  * `-f`: La ruta al diccionario de subdominios. **Seclists** (`/usr/share/seclists/`) es una fuente excelente para estos diccionarios.
  * `<dominio>`: El dominio objetivo (ej. `realcorp.htb`).

### Ejemplo de Ejecución y Resultados

```bash
dnsenum --dnsserver 10.10.10.224 --threads 50 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt realcorp.htb
```

**Salida:**

```
Brute forcing with /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:
______________________________________________________________________________________

ns.realcorp.htb.                  259200   IN    A       10.197.243.77
proxy.realcorp.htb.               259200   IN    CNAME   ns.realcorp.htb.
wpad.realcorp.htb.                259200   IN    A       10.197.243.31
```

  * **Análisis de Resultados (Pentesting)**:
      * `ns.realcorp.htb`: Un servidor de nombres con la IP `10.197.243.77`. Es un punto de referencia clave.
      * `proxy.realcorp.htb`: Un alias (`CNAME`) que apunta a `ns.realcorp.htb`. Esto podría indicar que el mismo host gestiona el tráfico de proxy y DNS.
      * `wpad.realcorp.htb`: Este es un hallazgo muy interesante. WPAD (Web Proxy Auto-Discovery Protocol) es utilizado por los navegadores para encontrar automáticamente la configuración de proxy. Un host `wpad` es un objetivo de alto valor para ataques de **Man-in-the-Middle (MitM)**, ya que si podemos suplantarlo, podríamos interceptar todo el tráfico web de los clientes de la red.

## 2\. Enumeración con `gobuster dns`

`gobuster` es una herramienta escrita en Go, conocida por su increíble velocidad. Es ideal para realizar fuerza bruta de subdominios de forma muy eficiente, especialmente con diccionarios grandes.

### Comando

```bash
gobuster dns -d <dominio> -r <IP_Servidor_DNS> -t 50 -w <ruta_diccionario> -i
```

  * `-d`: El dominio objetivo.
  * `-r`: El "resolver" o servidor DNS a utilizar.
  * `-t`: Número de hilos.
  * `-w`: Ruta al diccionario.
  * `-i`: Muestra las IPs de los subdominios encontrados, lo que es muy útil.

### Ejemplo de Ejecución y Resultados

```bash
gobuster dns -d realcorp.htb -r 10.10.10.224 -t 50 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -i
```

**Salida:**

```
===============================================================
Found: ns.realcorp.htb [10.197.243.77]
Found: proxy.realcorp.htb [10.197.243.77]
Found: wpad.realcorp.htb [10.197.243.31]
===============================================================
```

  * **Análisis de Resultados**: `gobuster` confirma rápidamente los mismos subdominios que `dnsenum`. Su simplicidad y velocidad lo hacen perfecto para una primera pasada rápida o para validar los resultados de otras herramientas.

### Siguientes Pasos

1.  **Añadir los subdominios al `/etc/hosts`**: Para poder acceder a ellos por su nombre desde nuestra máquina de ataque.
    ```
    10.197.243.77   ns.realcorp.htb proxy.realcorp.htb
    10.197.243.31   wpad.realcorp.htb
    ```
2.  **Escanear los nuevos hosts**: Realizar un escaneo de puertos (con `nmap`, por ejemplo) a las nuevas IPs descubiertas (`10.197.243.77` y `10.197.243.31`) para identificar qué servicios están corriendo en ellas.