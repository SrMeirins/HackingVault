# Manual Host Scan Ping

Cuando tenemos acceso a una máquina en un entorno, y vemos que tenemos una interfaz de red interna y queremos hacer una enumeración de hosts de esa red, aunque tenemos la opción de subir un ejecutable o binario de nmap, tenemos otras maneras de realizar un escaneo de hosts a ver cuales están levantados.

## Linux

#### One Liner
```bash
for i in $(seq 1 254); do (ping -c 1 172.18.0.$i | grep "bytes from" | cut -d':' -f1 | cut -d' ' -f4 &);done
```
#### Pequeño Script
```bash
#!/bin/bash

function ctrl_c(){
	echo -e "\n\n[!] Saliendo .... \n"
	exit 1
}

#Ctrl_C
trap ctrl_c INT

network="172.18.0"
for i in $(seq 1 254);do
	timeout 1 bash -c "ping -c 1 $network.$i" &>/dev/null && echo -e "[+] HOST ACTIVO - $network.$i" &
done; wait
```