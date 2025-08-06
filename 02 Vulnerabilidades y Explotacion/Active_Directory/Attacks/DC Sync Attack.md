# **DCSync Attack en Pentesting**

**DCSync** es un ataque que permite a un atacante obtener las contraseñas y hashes de las cuentas de usuario en un dominio de Active Directory (AD) sin necesidad de acceder directamente a los Controladores de Dominio. Este ataque se aprovecha de los permisos que ciertos usuarios tienen en el dominio, específicamente los permisos de **GetChanges** y **GetChangesAll**, que les permiten solicitar la replicación de datos entre los Controladores de Dominio.

### **¿Cómo Funciona el DCSync Attack?**

En Active Directory, los Controladores de Dominio (DCs) replican información entre sí usando el **Protocolo Remoto de Replicación de Directorio (MS-DRSR)**. Este protocolo es esencial para mantener la sincronización entre los diferentes Controladores de Dominio. Sin embargo, debido a que MS-DRSR es una función válida y necesaria de AD, no puede ser desactivada, lo que lo convierte en un vector de ataque.

El **DCSync** simula el comportamiento de un Controlador de Dominio y solicita a otros Controladores de Dominio que le repliquen información, como las contraseñas de las cuentas de usuario. Cuando un atacante tiene permisos de replicación sobre el dominio, puede obtener los hashes de las contraseñas de cuentas de alto privilegio, como las de los administradores del dominio, y en algunos casos incluso obtener las contraseñas en texto claro si están almacenadas con cifrado reversible.

### **Permisos Necesarios**

Por defecto, solo los siguientes grupos de usuarios tienen los permisos necesarios para realizar un **DCSync attack**:
- **Domain Admins**
- **Enterprise Admins**
- **Administradores**
- **Controladores de Dominio**

Si un atacante tiene acceso a un usuario con permisos de replicación, como los mencionados (usualmente a través de un compromiso previo en la red), puede realizar el ataque.

### **Recuperación de Contraseñas en Texto Claro**

Si la cuenta de un usuario tiene la opción de **"Almacenar la contraseña con cifrado reversible"** habilitada, es posible que la contraseña sea recuperable en texto claro mediante el uso de herramientas como **Mimikatz**.

---

## **Herramientas y Comandos para Ejecutar un DCSync Attack**

### **1. Mimikatz**

**Mimikatz** es una herramienta ampliamente utilizada en pentesting para realizar ataques de **DCSync**, entre otras funcionalidades como la extracción de hashes y la ejecución de ataques Pass-the-Hash.

#### **Comando de Mimikatz para DCSync:**

```bash
mimikatz lsadump::dcsync /domain:testlab.local /user:Administrator
```

- **lsadump::dcsync**: Módulo de Mimikatz que simula la replicación de un Controlador de Dominio.
- **/domain:testlab.local**: Especifica el dominio al que pertenece el usuario.
- **/user:Administrator**: El nombre de usuario cuya información de cuenta será replicada.

Este comando hará que Mimikatz intente replicar las contraseñas del usuario **Administrator** desde el Controlador de Dominio del dominio `testlab.local`.

### **2. Impacket's SecretsDump**

**SecretsDump** de Impacket es otra herramienta potente para ejecutar un ataque **DCSync**. Funciona de manera similar a Mimikatz y puede ser ejecutado de forma remota si se tienen las credenciales necesarias.

#### **Comando de SecretsDump:**

```bash
impacket-secretsdump htb.local/mrlky:Football#7@10.10.10.103
```

- **htb.local**: El dominio al que pertenece el usuario.
- **mrlky:Football#7**: El nombre de usuario y la contraseña de la cuenta que tiene permisos para ejecutar el ataque.
- **10.10.10.103**: La dirección IP del Controlador de Dominio.

Este comando utiliza **SecretsDump** para realizar un ataque **DCSync** y extraer las contraseñas o hashes de las cuentas del dominio, especificando la IP del Controlador de Dominio.
