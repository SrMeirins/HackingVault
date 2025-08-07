# **Escaneo de Redes con Nmap sobre IPv6**

En la fase de reconocimiento, es crucial no pasar por alto las direcciones **IPv6**. A menudo, los sistemas tienen una doble pila de red (IPv4 e IPv6), y no es raro encontrar que las reglas de firewall aplicadas al tráfico IPv4 no han sido replicadas para IPv6, dejando puertos y servicios expuestos.

## **Descubrimiento de Direcciones IPv6**

Las direcciones IPv6 pueden descubrirse de varias maneras durante la enumeración. Una fuente muy común es a través de servicios de monitorización como **SNMP**, que pueden filtrar listas completas de interfaces de red y sus direcciones IP configuradas, tanto v4 como v6.

## **Escaneo de Puertos con Nmap sobre IPv6**

Para indicarle a Nmap que utilice el protocolo IPv6 en lugar de IPv4, simplemente se añade el flag `-6`. El resto de los parámetros funcionan de la misma manera.

### **1. Escaneo Rápido de Todos los Puertos**

Al igual que con IPv4, un primer paso útil es realizar un escaneo rápido de todos los puertos para identificar qué está abierto.

```bash
nmap -p- -sS --min-rate 5000 --open -Pn -n -6 dead:beef::250:56ff:fe94:ceb0 -oA nmap_simple_scan_ipv6
```

  * **`-6`**: Este es el flag clave que fuerza a Nmap a usar IPv6.
  * **`dead:beef::250:56ff:fe94:ceb0`**: La dirección IPv6 del objetivo.

### **2. Escaneo Dirigido de Servicios**

Una vez identificados los puertos abiertos, se puede lanzar un escaneo más profundo para enumerar versiones y ejecutar scripts básicos.

```bash
nmap -sCV -p22,80 -Pn -n -6 dead:beef::250:56ff:fe94:ceb0 -oA nmap_simple_scan_ipv6
```

#### **Ejemplo de Salida y Análisis**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2a:90:a6:b1:e6:33:85:07:15:b2:ee:a7:b9:46:77:52 (RSA)
|_  256 3f:1c:77:93:5c:c0:6c:ea:26:f4:bb:6c:59:e9:7c:b0 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: 400 Bad Request
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| address-info: 
|   IPv6 EUI-64: 
|     MAC address: 
|       address: 00:50:56:94:ce:b0
|_      manuf: VMware
```

  * **Información Obtenida:** El escaneo nos revela las versiones exactas de **OpenSSH** y **Apache**, información vital para buscar exploits.
  * **EUI-64 y MAC Address:** El script `address-info` puede incluso derivar la **dirección MAC** del host a partir de su dirección IPv6 EUI-64, confirmando en este caso que se trata de una máquina virtual VMware.