# Transferencia de Archivos: Linux a Linux

Esta entrada describe técnicas generales para transferir archivos desde un sistema Linux a uno Linux. 

## Base64 Encoding-Decoding

Si se trata de archivos sencillos y pequeños, se puede jugar con `base64`:

```bash
# Máquina Host
base64 -w 0 portScan.sh| xclip -sel clip

# Máquina Destino
echo 'base64cadena...." | base64 -d > archivo.extension
```