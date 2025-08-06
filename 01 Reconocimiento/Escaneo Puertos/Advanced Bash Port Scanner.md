
```bash
#!/bin/bash

# Valida que se haya proporcionado la red en formato CIDR
if [ -z "$1" ]; then
  echo "[-] Uso: $0 <red_en_formato_CIDR>"
  echo "[-] Ejemplo: $0 10.197.251.0/24"
  exit 1
fi

# Extrae el prefijo de la red del argumento
NETWORK_PREFIX=$(echo $1 | cut -d'/' -f1 | cut -d'.' -f1-3)
COMMON_PORTS="21 22 25 53 80 88 135 139 443 445 3306 3389 5985 8080"

echo "[*] Iniciando escaneo en la red $1..."
echo "[*] Puertos a verificar: ${COMMON_PORTS}"
echo "----------------------------------------------------"

# Itera a través de todos los hosts en la red /24
for host in $(seq 1 254); do
  IP="${NETWORK_PREFIX}.${host}"
  
  for port in ${COMMON_PORTS}; do
    # Se usa 'nc' (netcat) que es más estable con proxychains
    # -z: Modo "Zero-I/O", solo comprueba la conexión.
    # -w 1: Timeout de 1 segundo para la conexión.
    (
      proxychains4 -q nc -z -w 1 ${IP} ${port} 2>/dev/null && \
        echo "[+] Puerto Abierto: ${IP}:${port}"
    ) &
  done
done

# Espera a que todos los procesos en segundo plano terminen
wait

echo "----------------------------------------------------"
echo "[*] Escaneo completado."
```

### **¿Cómo Utilizarlo?**

1.  **Guarda el script** en un archivo (por ejemplo, `scan.sh`).
2.  **Dale permisos de ejecución**:
    ```bash
    chmod +x scan.sh
    ```
3.  **Ejecútalo** pasando la red que quieres escanear como argumento:
    ```bash
    ./scan.sh 10.197.251.0/24
    ```
4.  **Nota**
    Aunque podamos pasarle el CIDR, unicamente esta configurado para redes /24. Hay que tenerlo en cuenta. Importante tambien pasarle la red correcta.