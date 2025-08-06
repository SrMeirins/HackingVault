# **Descubrimiento de Hosts Internos con Búsqueda Inversa de DNS**

Cuando se obtiene acceso a un nuevo segmento de red, especialmente a través de un túnel o un proxy lento, escanear el rango completo de IPs (ej. una red `/24`) con herramientas como `nmap` o scripts de Bash puede ser extremadamente ineficiente y ruidoso.

Una técnica mucho más elegante y dirigida es realizar una **búsqueda inversa de DNS** (Reverse DNS Lookup) en todo el rango de red.

## 1\. ¿En qué consiste la Búsqueda Inversa de DNS?

A diferencia de una búsqueda DNS normal, donde se consulta el nombre de un host para obtener su dirección IP (Registro A), una búsqueda inversa hace lo contrario: **se consulta una dirección IP para obtener el nombre de host asociado a ella** (Registro PTR).

**¿Por qué es útil en pentesting?**

En entornos corporativos bien administrados, los servidores y dispositivos importantes suelen tener registros PTR asignados. Las direcciones IP que no están en uso, simplemente no tendrán un registro.

Por lo tanto, al realizar una búsqueda inversa en un rango de red completo, podemos filtrar rápidamente los cientos de IPs vacías y **centrarnos únicamente en los hosts que están activos y configurados**, que son nuestros objetivos de interés.

## 2\. La Herramienta: `dnsrecon`

`dnsrecon` es una herramienta de enumeración DNS muy potente. Una de sus funcionalidades clave es la capacidad de realizar búsquedas inversas en rangos de red completos.

### Comando

```bash
dnsrecon -r <rango_de_red_CIDR> -n <IP_Servidor_DNS> -d <dominio>
```

  * **`-r <rango_de_red_CIDR>`**: El rango de IP que se desea escanear (ej. `10.241.251.0/24`).
  * **`-n <IP_Servidor_DNS>`**: El servidor DNS que se utilizará para realizar las consultas. Es fundamental usar el DNS interno al que tenemos acceso.
  * **`-d <dominio>`**: El dominio objetivo. `dnsrecon` intentará validar que los nombres de host encontrados pertenecen a este dominio.

## 3\. Descubrimiento de un Host (Caso Práctico)

Tras identificar la nueva red interna `10.241.251.0/24`, en lugar de escanearla por fuerza bruta, se utiliza `dnsrecon` para realizar una búsqueda inversa.

```bash
dnsrecon -r 10.241.251.0/24 -n 10.10.10.224 -d realcorp.htb
```

**Resultado Obtenido:**

```
[*] Performing Reverse Lookup from 10.241.251.0 to 10.241.251.255
[+]      PTR srvpod01.realcorp.htb 10.241.251.113
[+] 1 Records Found
```

### Análisis del Resultado y Ventajas

  * **Eficiencia Máxima**: En lugar de escanear 254 posibles direcciones IP, la búsqueda inversa nos ha dado **un único objetivo de alto valor**: `10.241.251.113`.
  * **Inteligencia Adicional**: No solo tenemos la IP, sino también su nombre de host: `srvpod01.realcorp.htb`. Este nombre puede darnos pistas sobre la función del servidor (ej. "Server POD 01", podría ser parte de una infraestructura de contenedores como Docker/Kubernetes o simplemente una convención de nomenclatura).
  * **Reducción de Ruido**: Este método es mucho más sigiloso que un escaneo de puertos masivo.

## 4\. Siguientes Pasos

Una vez identificado el host, el plan de acción es claro y dirigido:

1.  **Añadir el nuevo host al archivo `/etc/hosts`**:
    ```
    10.241.251.113  srvpod01.realcorp.htb
    ```
2.  **Realizar un escaneo de puertos exhaustivo y dirigido**: Ahora que tenemos un objetivo concreto, podemos lanzar un `nmap` completo, pero solo contra esta IP. El escaneo será mucho más rápido y manejable.
    ```bash
    sudo proxychains4 -q nmap -p- -sT -sV -sC -A -oN nmap_srvpod01 10.241.251.113
    ```