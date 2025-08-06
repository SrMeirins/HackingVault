# **Pass-the-Hash (PTH) en Pentesting**

**Pass-the-Hash** (PTH) es una técnica de ataque en la que un atacante utiliza el hash de una contraseña, en lugar de la contraseña en texto claro, para autenticarse en un sistema. En redes Windows, cuando un usuario se autentica, su contraseña es convertida en un hash (por ejemplo, NTLM) y se usa para validación. Si un atacante obtiene este hash, puede usarlo para autenticarse sin conocer la contraseña real.

En el contexto de **pentesting**, **Pass-the-Hash** se utiliza para escalar privilegios o moverse lateralmente dentro de la red al obtener hashes de contraseñas (como el hash de un administrador) y usarlos para acceder a otros sistemas de la red.

---

## **Herramienta: WMIExec (Impacket)**

**WMIExec** es una herramienta en el paquete **Impacket** que permite ejecutar comandos de forma remota sobre sistemas Windows utilizando **Windows Management Instrumentation (WMI)**. Con un hash de la contraseña, se puede realizar un ataque Pass-the-Hash para ejecutar comandos sin conocer la contraseña en texto claro.

### **Comando:**

```bash
impacket-wmiexec htb.local/Administrator@10.10.10.103 -hashes :f6b7160bfc91823792e0ac3a162c9267
```

### **Explicación del Comando:**
- **htb.local/Administrator**: Usuario y dominio.
- **10.10.10.103**: Dirección IP del sistema objetivo.
- **-hashes :f6b7160bfc91823792e0ac3a162c9267**: El hash NTLM de la contraseña del usuario `Administrator`.

Este comando usa **WMIExec** para ejecutar comandos de forma remota en el sistema objetivo, utilizando el hash de la contraseña para autenticarse.
