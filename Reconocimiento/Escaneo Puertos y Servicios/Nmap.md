# **NMAP**

**Nmap (Network Mapper)** es una herramienta de código abierto muy popular utilizada para el escaneo de redes y auditoría de seguridad. Permite descubrir dispositivos y servicios en una red, identificar puertos abiertos, detectar sistemas operativos y obtener información detallada sobre la configuración de los servicios. Nmap es ampliamente utilizado en pruebas de penetración, auditorías de seguridad y actividades de reconocimiento.

Nmap proporciona múltiples opciones de escaneo, lo que permite realizar un análisis exhaustivo de redes con distintos protocolos, y su flexibilidad se extiende a los resultados, permitiendo la exportación a diversos formatos.

A continuación, se describen algunos de los comandos más utilizados y avanzados para realizar escaneos con Nmap:

---

## **Escaneo SYN Connect para Linux**

Para realizar un escaneo completo de puertos en Linux utilizando la opción SYN connect, el comando sería el siguiente:

```bash
nmap -p- --open -T5 -n -v -Pn {IP} -oN allPorts
```

**Explicación de los parámetros:**
- **`-p-`**: Escanea todos los puertos (1-65535).
- **`--open`**: Muestra solo los puertos abiertos.
- **`-T5`**: Ajuste de temporización para una exploración más rápida.
- **`-n`**: No resuelve nombres de host (reduce el tiempo de escaneo).
- **`-v`**: Modo verbose para más detalles durante el escaneo.
- **`-Pn`**: Omite la detección de host (asume que el objetivo está activo).
- **`-oN allPorts`**: Guarda el resultado en un archivo de texto plano.

---

## **Escaneo SYN Connect para Windows**

Si el escaneo normal tarda demasiado, puedes realizar un escaneo con **SYN** especificando una **velocidad mínima** de paquetes para acelerar el proceso:

```bash
nmap -p- --open -sS --min-rate 5000 -n -vvv -Pn {IP} -oN allPorts
```

**Explicación de los parámetros:**
- **`-sS`**: Realiza un escaneo SYN (SYN scan).
- **`--min-rate 5000`**: Ajusta la tasa mínima de envío de paquetes a 5000 paquetes por segundo para acelerar el escaneo.
- **`-vvv`**: Aumenta la cantidad de salida detallada del escaneo.

---

## **Escaneo UDP**

Los escaneos UDP suelen ser muy lentos debido a la naturaleza de UDP, por lo que se recomienda limitar los puertos que se escanean:

```bash
nmap --top-ports 100 --open -sU -v -T5 -n {IP} -oG allPortsUDP
```

**Explicación de los parámetros:**
- **`--top-ports 100`**: Escanea los 100 puertos más comunes de UDP.
- **`-sU`**: Escaneo de puertos UDP.
- **`-T5`**: Ajuste de temporización para un escaneo más rápido.
- **`-oG`**: Salida en formato **grepable**.

---

## **Exportar Resultados de Nmap a HTML**

Si tienes un escaneo con muchos puertos y deseas exportar los resultados a un archivo **HTML**, primero debes guardar el resultado en formato XML y luego convertirlo con la herramienta `xsltproc`.

1. **Comando para exportar el escaneo a XML**:

```bash
-oX targetedXML
```

2. **Convertir el archivo XML a HTML**:

```bash
xsltproc targetedXML > targetedHTML
```

3. **Montar un servidor web local para ver los resultados**:

```bash
php -S 0.0.0.0:80
```

Esto te permitirá visualizar el informe en un navegador web de forma limpia y organizada.
