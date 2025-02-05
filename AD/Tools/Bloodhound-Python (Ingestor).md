# **Ingestor en Python para BloodHound de Forma Remota**

Cuando tenemos credenciales válidas y acceso a la red del dominio, podemos obtener remotamente la información necesaria para alimentar BloodHound sin tener que ejecutar scripts directamente en las máquinas del dominio. Utilizando **bloodhound-python**, podemos realizar una recopilación remota de datos de Active Directory.

### **Comando básico:**

```bash
bloodhound-python -c All -u 'Amanda' -p 'Ashare1972' -ns 10.10.10.103 -d htb.local
```

### **Explicación de los parámetros:**
- **-c All**: Recopila toda la información posible del dominio (usuarios, grupos, permisos, etc.).
- **-u 'Amanda'**: Nombre de usuario con permisos de lectura en el dominio.
- **-p 'Ashare1972'**: Contraseña del usuario.
- **-ns 10.10.10.103**: Dirección IP del controlador de dominio.
- **-d htb.local**: Nombre del dominio.

### **Proceso:**
1. El comando recolecta datos del dominio de manera remota.
2. Los datos se exportan en archivos JSON que incluyen detalles sobre usuarios, grupos y permisos.
3. Los archivos JSON generados se pueden importar directamente en la interfaz de **BloodHound** para su análisis.

Este método permite realizar una auditoría de AD sin necesidad de tener acceso físico al dominio, utilizando solo las credenciales proporcionadas y acceso remoto a la red.
