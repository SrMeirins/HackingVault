# LDAP Pass-Back Attack en Impresoras

El ataque LDAP Pass-Back en impresoras consiste en reconfigurar un dispositivo de impresión para que envíe sus credenciales LDAP (ya sea en texto plano por el puerto 389 o en forma de challenge/response NTLM) a un servidor controlado por el atacante. Una vez capturadas, esas credenciales pueden usarse directamente o hacer relay NTLM hacia un servicio Windows para lograr acceso. EN este caso explicaremos el ejemplo sencillo de un Simple Bind PlainText

## Desglose Ataque Plain Text

### 1. Preparar el entorno de ataque
1. Configurar máquina atacante en la misma red que la impresora
2. Asegurarse de tener privilegios para capturar el tráfico y responder a peticiones LDAP.

### 2. Captura de credenciales LDAP Simple (Plaintext NC)
1. En este punto deberíamos activar un ataque MITM para redirigir el tráfico LDAP de la impresora hacia nosotros, por ejemplo con herramientas como `ettercap` o `arpspoof`. En nuestro caso particular, ha resultado más sencillo ya que tenemos acceso al panel de Settings de la impresora, donde podemos modificar el `Server Address` y `Server Port`. Además, tenemos acceso a la visualización de un nombre de usuario.

2. Ejecutar `nc -lvnp 389` para ponernos a la escucha de paquetes por el puerto 389:
3. Forzar a la impresora a realizar una operación LDAP: por ejemplo desde la interfaz web, hacer un Test LDAP o configurar un escaneo a correo que busque usuarios en el directorio.
4. Nos llega una conexión entrante ofreciendonos contraseña en texto claro.

### Captira de credenciales LDAP Simple (Plaintext Tshark)
1. Si queremos capturar de manera mas organizada podemos usar `tcpdump` para luego visualizar el Simple Bind a través de `tshark`. Para ello necesitamos aún así ponernos antes a la escucha por `netcat` también: `nc -lvnp 389`
2. Vamos a realizar una captura de tráfico ldap mediante la herramienta `tcpdump`
    ```sh
    sudo tcpdump -i tun0 port 389 -w ldap_plain.pcap
    ```
3. Forzar a la impresora a realizar una operación LDAP: por ejemplo desde la interfaz web, hacer un Test LDAP o configurar un escaneo a correo que busque usuarios en el directorio.
4. Paramos la orden de captura, y vamos a abrir aplicando una serie de filtros esa captura de tráfico con `tshark`:
    ```sh
    tshark -r ldap_plain.pcap -Y 'ldap.protocolOp == 0' -O ldap
    ```
    - `-Y` Aplica una serie de filtros de visualización para mostrar solo los paquetes LDAP de tipo Bind Request.
    - `-O ldap` Limita la salida a mostrar solo el protocolo LDAP, ignorando capas IP, TCP...
5. Si nos fijamos en la info, podemos ver la contraseña en texto claro en el campo `simple`. Si queremos ver esa info directamente podemos jugar con los campos del paquete para filtrar directamente por la password:
    ```zsh
    tshark -r ldap_plain.pcap -Y 'ldap.protocolOp == 0' -T fields -e ldap.simple
    ```
## Mitigaciones

- Deshabilitar el Simple Bind en la impresora o forzar LDAPS con certificado validado
- Configurar un Firewall que solo permita a la impresora comunicarse con servidores LDAP legítimos
- Segmentación de red

