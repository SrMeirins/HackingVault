# **Kerberoasting en Pentesting**  

**Kerberoasting** es un ataque contra el protocolo **Kerberos** que permite a un atacante con una cuenta sin privilegios en un dominio de **Active Directory (AD)** obtener los **hashes de contraseña** de las cuentas de servicio. Posteriormente, estos hashes pueden ser descifrados fuera de la red para recuperar las contraseñas en texto claro.  

---

## **¿Cómo Funciona el Kerberoast Attack?**  

1. Un usuario autenticado en AD solicita acceso a un servicio en la red.  
2. El **Controlador de Dominio (KDC)** responde con un **Ticket Granting Service (TGS)** cifrado con la clave de la cuenta de servicio asociada.  
3. Como la clave del servicio es derivada de su contraseña, un atacante puede solicitar estos tickets TGS y extraer su contenido.  
4. Luego, los **TGS pueden ser crackeados** con herramientas como **John the Ripper** o **Hashcat** para recuperar la contraseña de la cuenta de servicio.  

Este ataque **no requiere privilegios administrativos**, lo que lo hace atractivo para atacantes que buscan escalar privilegios dentro de un entorno de Active Directory.  

---

## **¿Dónde están almacenados los tickets TGS?**  

Los **tickets TGS no están almacenados globalmente en Active Directory**, sino que **se generan dinámicamente por el KDC** cuando un usuario solicita acceso a un servicio.  

- **Cada usuario autenticado** puede solicitar un TGS para cualquier cuenta de servicio y recibirlo en su máquina.  
- **No es necesario acceso a una máquina específica**, ya que el KDC entrega los tickets al usuario que los solicita desde cualquier equipo en el dominio.  
- **El atacante no necesita permisos elevados** para obtener estos tickets, solo credenciales válidas en el dominio.  

---

## **Herramientas y Comandos para Ejecutar un Kerberoast Attack**  

### **1. GetUserSPNs (Impacket)**  

El script `GetUserSPNs.py` de **Impacket** permite solicitar tickets de servicio y extraer los **TGS cifrados**, listos para ser crackeados.  

#### **Comando:**  
```bash
impacket-GetUserSPNs domain/user:password -request
```  
- **domain/user:password** → Usuario del dominio con su contraseña.  
- **-request** → Solicita los tickets de servicio (TGS).  

Este comando devolverá los tickets de servicio cifrados con las claves de las cuentas de servicio.  

---

### **2. Crackeo de Tickets con John the Ripper**  

Una vez obtenidos los tickets TGS, se pueden guardar en un archivo y crackearlos con **John the Ripper**:  

```bash
john --format=krb5tgs --wordlist=rockyou.txt tickets.hash
```  
- **--format=krb5tgs** → Indica el formato del hash de Kerberos.  
- **--wordlist=rockyou.txt** → Archivo de diccionario para probar contraseñas.  

---

### **3. Rubeus (Windows)**  

Si se tiene acceso a una máquina Windows dentro del dominio, **Rubeus.exe** permite realizar Kerberoasting directamente desde una sesión válida.  

#### **Comando en Windows:**  
```powershell
.\Rubeus.exe kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972 /nowrap
```  
- **/creduser:** Usuario de dominio.  
- **/credpassword:** Contraseña del usuario autenticado.  
- **/nowrap:** Formatea la salida para facilitar la extracción de los hashes.  
