```bash
#!/bin/bash

function ctrl_c(){
	echo -e "\n\n[!] Saliendo .... \n"
	exit 1
}

#Ctrl_C
trap ctrl_c INT

hosts=(172.19.0.2 172.19.0.4)
for host in ${hosts[@]};do
	echo -e "\n\n [+] Enumerando puertos para el host: $host\n"
	for port in $(seq 1 10000);do
		timeout 1 bash -c "echo '' > /dev/tcp/$host/$port" 2>/dev/null && echo -e "\t[+] Port $port - OPEN" &
	done; wait
done

```