**Impacket-psExec**

> 🚨 **Es necesario tener credenciales marcadas como Pwned en NXC / CME para su uso efectivo.** 🚨

Cuando contamos con credenciales privilegiadas (que NXC o CME marcan como Pwned), podemos utilizar la herramienta **Impacket-psexec** para obtener una shell remota en el sistema de destino. Esto se logra ejecutando el siguiente comando:

```
impacket-psexec domain/User:Password@ip cmd.exe
```

El comando ejecutará el shell `cmd.exe` de manera remota en la máquina objetivo, permitiéndonos interactuar con ella y realizar las acciones necesarias para la explotación o administración del sistema comprometido.
