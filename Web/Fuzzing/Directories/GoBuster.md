# **GoBuster**

**GoBuster** es una herramienta escrita en Go diseñada para realizar fuzzing en directorios y archivos de un servidor web. Es particularmente útil para encontrar rutas o recursos ocultos dentro de un sitio web, probando una lista de posibles nombres de directorios y archivos. GoBuster se utiliza comúnmente en pruebas de penetración y auditorías de seguridad para descubrir recursos no documentados o accesibles sin autenticación.

## **Escaneo de Directorios y Archivos**

Para realizar un escaneo de directorios y archivos en un servidor web, se utiliza el siguiente comando:

```bash
gobuster -u http://10.10.10.103/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x asp,aspx,txt,html
```

**Explicación de los parámetros:**
- **`-u`**: Especifica la URL del servidor web a escanear (en este caso, `http://10.10.10.103/`).
- **`-w`**: Define el archivo de diccionario (lista de palabras) que GoBuster utilizará para realizar fuzzing en los directorios y archivos. En este caso, se usa el diccionario de directorios **directory-list-2.3-small.txt**.
- **`-x`**: Especifica las extensiones que GoBuster debe probar en cada directorio o archivo encontrado. Aquí se están probando las extensiones **asp**, **aspx**, **txt**, y **html**.
