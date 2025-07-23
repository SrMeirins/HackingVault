### **Escalada de Privilegios Abusando de Permisos de `sudo`**

Una de las primeras comprobaciones a realizar tras obtener acceso a un sistema Linux es revisar los permisos de `sudo` del usuario actual. Una configuración incorrecta en el archivo `/etc/sudoers` puede proporcionar una vía directa para escalar privilegios a `root`.

#### **Comando Clave de Enumeración: `sudo -l`**

Este comando lista los comandos que el usuario actual puede ejecutar con `sudo`. Si se puede ejecutar sin que se pida contraseña, es una señal de alerta inmediata.

```bash
sudo -l
```

Una salida vulnerable típicamente se ve así:

```console
User user may run the following commands on this-host:
    (root) NOPASSWD: /usr/bin/nombre_binario
```

Esta línea indica que el usuario `user` puede ejecutar `/usr/bin/nombre_binario` como `root` y sin necesidad de introducir su contraseña. Muchos binarios estándar de Linux pueden ser abusados para lanzar una shell si se ejecutan con privilegios elevados.

-----

### **Binarios Explotables**

A continuación se listan diferentes binarios que, si están presentes en la salida de `sudo -l`, pueden ser utilizados para escalar privilegios.

#### **`/usr/bin/find`**

`find` es una utilidad para buscar archivos, pero su opción `-exec` permite ejecutar cualquier comando, heredando los privilegios con los que `find` fue lanzado.

##### **Comando de Explotación**

```bash
sudo /usr/bin/find . -exec /bin/bash \; -quit
```

  * **`sudo /usr/bin/find .`**: Ejecuta `find` como `root`.
  * **`-exec /bin/bash`**: Le indica a `find` (que es `root`) que ejecute una nueva shell de `bash`. Esta shell hereda los privilegios de `root`.
  * **`\; -quit`**: Finaliza el comando `-exec` y detiene `find` inmediatamente después de lanzar la shell.

**Resultado:** Se obtiene una shell de `root` interactiva.

-----
