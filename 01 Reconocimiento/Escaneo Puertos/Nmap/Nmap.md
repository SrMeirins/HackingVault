# **NMAP**

**Nmap (Network Mapper)** es una herramienta de código abierto muy popular utilizada para el escaneo de redes y auditoría de seguridad. Permite descubrir dispositivos y servicios en una red, identificar puertos abiertos, detectar sistemas operativos y obtener información detallada sobre la configuración de los servicios. Nmap es ampliamente utilizado en pruebas de penetración, auditorías de seguridad y actividades de reconocimiento.

Nmap proporciona múltiples opciones de escaneo, lo que permite realizar un análisis exhaustivo de redes con distintos protocolos, y su flexibilidad se extiende a los resultados, permitiendo la exportación a diversos formatos.

-----

## **Comandos de Escaneo Fundamentales**

A continuación, se describen algunos de los comandos más utilizados y avanzados para realizar escaneos con Nmap:

### **Escaneo para Sistemas Linux**

Para realizar un escaneo completo de puertos en Linux, el siguiente comando es una base sólida y eficiente.

```bash
nmap -p- --open -T5 -n -v -Pn {IP} -oN openPorts
```

**Explicación de los parámetros:**

  * **`-p-`**: Escanea todos los puertos (1-65535).
  * **`--open`**: Muestra solo los puertos abiertos.
  * **`-T5`**: (Ver sección de temporización) Ajuste de temporización "Insane" para una exploración muy rápida. Ideal para redes estables y CTFs.
  * **`-n`**: No resuelve nombres de host (reduce el tiempo de escaneo).
  * **`-v`**: Modo verbose para más detalles durante el escaneo.
  * **`-Pn`**: Omite la detección de host (asume que el objetivo está activo).
  * **`-oN openPorts`**: Guarda el resultado en un archivo de texto plano llamado `openPorts`.

-----

### **Escaneo para Sistemas Windows o Redes Lentas**

Para sistemas Windows, o cuando un escaneo normal es demasiado lento, se puede especificar un escaneo SYN (`-sS`) con una velocidad mínima de paquetes para acelerar el proceso de forma significativa.

```bash
nmap -p- --open -sS --min-rate 5000 -n -vvv -Pn {IP} -oN openPorts
```

**Explicación de los parámetros:**

  * **`-sS`**: Realiza un escaneo SYN (TCP SYN Scan), también conocido como "stealth scan". Es más rápido y sigiloso que un escaneo de conexión completa.
  * **`--min-rate 5000`**: Ajusta la tasa mínima de envío de paquetes a 5000 por segundo. Esto fuerza a Nmap a ser rápido incluso si detecta latencia.
  * **`-vvv`**: Aumenta la cantidad de salida detallada del escaneo.

-----

### **Escaneo UDP**

Los escaneos UDP suelen ser muy lentos. Es recomendable limitar los puertos que se escanean a los más comunes.

```bash
nmap --top-ports 200 --open -sU -v -n {IP} -oG allPortsUDP
```

**Explicación de los parámetros:**

  * **`--top-ports 200`**: Escanea los 200 puertos UDP más comunes.
  * **`-sU`**: Escaneo de puertos UDP.
  * **`-oG`**: Salida en formato **grepable**.

-----

## **Enumeración Avanzada de Servicios y Scripts**

Una vez descubiertos los puertos abiertos, el siguiente paso es identificar qué se está ejecutando en ellos.

### **Comando Combinado de Enumeración**

Este es el comando "todo en uno" que se suele lanzar sobre los puertos específicos que se han encontrado abiertos.

```bash
nmap -p{PUERTOS} -sV -sC -oN targeted {IP}
```

#### **-sV (Detección de Versiones)**

Este parámetro le pide a Nmap que intente determinar la **versión exacta del servicio** que se está ejecutando en cada puerto abierto.

  * **¿Cómo funciona?** Envía una serie de sondas específicas para cada protocolo (HTTP, FTP, SSH, etc.) y analiza las respuestas para identificar el software y su versión.
  * **¿Por qué es crucial?** Conocer la versión exacta (ej. "Apache httpd 2.4.41") permite buscar vulnerabilidades y exploits conocidos para ese software específico en bases de datos como Exploit-DB.

#### **-sC (Scripts de Enumeración Básicos)**

Este parámetro ejecuta un conjunto de scripts de **Nmap Scripting Engine (NSE)** considerados como "default". Estos scripts realizan una enumeración básica y segura para obtener más información del servicio.

  * **¿Qué hacen?** Depende del servicio. En un servidor web, pueden buscar archivos `robots.txt` o extraer el título de la página. En un servidor SMB, pueden intentar listar recursos compartidos. En un servidor FTP, pueden comprobar si el inicio de sesión anónimo está habilitado.
  * **¿Por qué es útil?** Automatiza los primeros pasos de la enumeración, ahorrando tiempo y revelando a menudo información de bajo nivel pero muy valiosa (low-hanging fruit).

-----

## **Técnicas de Evasión y Detección de Firewalls**

A veces, los escaneos estándar son bloqueados por un firewall. Nmap ofrece técnicas para analizar el comportamiento del firewall.

### **Escaneo ACK para Mapear Reglas de Firewall**

El escaneo ACK (`-sA`) es diferente: **no determina si un puerto está abierto**, sino si está **filtrado** por un firewall con estado (stateful).

```bash
nmap -sA -v {IP}
```

  * **¿Cómo funciona?** Envía paquetes TCP con solo el flag ACK activado.
      * Si recibe una respuesta **RST (Reset)**, significa que el paquete llegó al host y el puerto **no está filtrado**.
      * Si **no recibe respuesta**, significa que un firewall con estado probablemente bloqueó el paquete, y el puerto **está filtrado**.
  * **¿Cuándo usarlo?** Es una excelente técnica para mapear el conjunto de reglas de un firewall y entender qué tipo de tráfico permite pasar, incluso si no puedes determinar si los puertos están abiertos.

### **Otros Escaneos Sigilosos (FIN, NULL, XMAS)**

Estos escaneos (`-sF`, `-sN`, `-sX`) son aún más sigilosos que el SYN scan y están diseñados para evadir firewalls y sistemas de detección de intrusos (IDS) simples que solo monitorizan paquetes SYN.

  * **`-sF` (FIN Scan):** Envía un paquete con solo el flag FIN.
  * **`-sN` (NULL Scan):** Envía un paquete sin ningún flag activado.
  * **`-sX` (XMAS Scan):** Envía un paquete con los flags FIN, PSH y URG activados (como un árbol de Navidad).

**Funcionamiento:** Un sistema compatible con RFC 793 debería responder con un RST si el puerto está cerrado, y no responder nada si está abierto. No funcionan en sistemas Windows.

-----

## **Control de Temporización (-T0 a -T5)**

Nmap ofrece plantillas de temporización para controlar la velocidad y el sigilo del escaneo. Van desde extremadamente lentas y sigilosas hasta muy rápidas y ruidosas.

  * **`-T0` (Paranoid):** Extremadamente lento. Usado para evadir IDS muy sensibles. Puede tardar horas.
  * **`-T1` (Sneaky):** Muy lento. Similar a T0 pero un poco más rápido.
  * **`-T2` (Polite):** Lento y consume poco ancho de banda. Diseñado para no sobrecargar redes inestables.
  * **`-T3` (Normal):** Es la opción por defecto. Un buen equilibrio entre velocidad y sigilo.
  * **`-T4` (Aggressive):** Rápido. Asume que estás en una red rápida y fiable. Ideal para CTFs y auditorías donde el sigilo no es la máxima prioridad.
  * **`-T5` (Insane):** Muy rápido. Puede sacrificar precisión y sobrecargar el objetivo o la red. Solo para redes muy rápidas y cuando tienes permiso para ser ruidoso.

-----

## **Exportar Resultados de Nmap a HTML**

Si tienes un escaneo con muchos puertos y deseas exportar los resultados a un archivo **HTML**, primero debes guardar el resultado en formato XML y luego convertirlo con la herramienta `xsltproc`.

1.  **Comando para exportar el escaneo a XML**:
    ```bash
    -oX targeted.xml
    ```
2.  **Convertir el archivo XML a HTML**:
    ```bash
    xsltproc targeted.xml -o targeted.html
    ```
3.  **Montar un servidor web local para ver los resultados**:
    ```bash
    python3 -m http.server 8000
    ```
    Esto te permitirá visualizar el informe en un navegador web de forma limpia y organizada.