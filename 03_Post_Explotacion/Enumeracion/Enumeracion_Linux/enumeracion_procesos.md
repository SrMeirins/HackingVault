## Comando `ps`

El comando `ps` es esencial para visualizar y entender los procesos que se ejecutan en un sistema Linux.

### **Comandos `ps` más usados en Pentesting**

* **`ps aux`**:
    * **`a`**: Muestra **todos** los procesos, incluyendo los de otros usuarios.
    * **`u`**: Formato orientado al **usuario** (columnas como `USER`, `%CPU`, `%MEM`, etc.).
    * **`x`**: Incluye procesos que **no tienen terminal de control** (daemons, servicios).
    * **Uso**: Proporciona una visión general completa de todos los procesos en el sistema.

* **`ps -ef`**:
    * **`-e`**: Muestra **todos** los procesos (equivalente a `-A`).
    * **`-f`**: Formato **"full"**, incluyendo la línea de comando completa.
    * **Uso**: Similar a `ps aux`, pero a menudo preferido por ver la línea de comando completa.

* **`ps -faux`**:
    * **`-f`**: Muestra los procesos en un formato de **árbol ASCII** (jerarquía padre/hijo), muy útil para ver quién lanzó qué.
    * **`a`**: Incluye procesos de **otros usuarios** asociados a un TTY.
    * **`u`**: Formato orientado al **usuario**.
    * **`x`**: Incluye procesos **sin TTY**.
    * **Uso**: Excelente para visualizar la jerarquía de procesos y detectar anomalías en la forma en que los procesos se inician.

---

### **Opciones Comunes de `ps` para Filtrado**

Usa estas opciones para acotar la salida de `ps` y encontrar información específica:

* **`-u <UID_o_Nombre>` / `--user <UID_o_Nombre>`**: Filtrar procesos ejecutados por un **usuario** específico.
    * **Ejemplo**: `ps -u root` (para ver los procesos de root).
* **`-p <PID>` / `--pid <PID>`**: Mostrar información sobre un **proceso por su ID**.
    * **Ejemplo**: `ps -p 1234` (para inspeccionar el proceso con PID 1234).
* **`-C <Comando>`**: Filtrar por el **nombre del comando** del proceso.
    * **Ejemplo**: `ps -C apache2` (para ver todos los procesos de Apache).
* **`-t <TTY>`**: Mostrar procesos asociados a un **terminal** específico.
    * **Ejemplo**: `ps -t pts/0`

---

### **Opciones Comunes de `ps` para Formato de Salida**

Personaliza qué columnas de información quieres ver:

* **`-o <formato_personalizado>` / `--format <formato_personalizado>`**: Define las **columnas** exactas que quieres ver. Puedes combinar nombres de campos separados por comas.
    * **Campos útiles**: `pid`, `user`, `command`, `%cpu`, `%mem`, `rss` (memoria residente), `vsz` (memoria virtual), `etime` (tiempo de ejecución).
    * **Ejemplo**: `ps -eo pid,user,command,etime` (muestra PID, usuario, comando y tiempo de ejecución).
* **`-l`**: Muestra el formato **"largo"**, incluyendo más detalles como el estado del proceso (`STAT`), la prioridad (`PRI`), etc.
    * **Ejemplo**: `ps -l aux`