# **Extracción de Credenciales de la Base de Datos en Drupal**  

Cuando tenemos acceso a los archivos de configuración de un sitio **Drupal**, podemos extraer credenciales de bases de datos, ya sea por acceso directo al sistema de archivos o mediante vulnerabilidades como **LFI (Local File Inclusion)**.  

📌 **Archivo objetivo:**  
📂 `sitename/sites/default/settings.php`  

---

## **¿Cómo Funciona la Extracción de Credenciales?**  

1. **Drupal almacena las credenciales en `settings.php`**, dentro de la carpeta `sites/default/`.  
2. Este archivo contiene la configuración de conexión a la base de datos, incluyendo el usuario y la contraseña.  
3. Si tenemos acceso al servidor o logramos leer el archivo mediante una vulnerabilidad (LFI, RCE, etc.), podemos extraer estos datos.  

---

## **Comandos para Buscar Credenciales**  

Si tenemos acceso al sistema de archivos de Drupal, podemos buscar credenciales con:  

```bash
grep -r "password" | less -S
```

### **Explicación de los argumentos:**  
- **`grep -r "password"`** → Busca de forma recursiva cualquier línea que contenga la palabra "password".  
- **`| less -S`** → Permite desplazarnos horizontalmente sin cortar las líneas largas.  

Si obtenemos acceso al archivo, podemos leerlo directamente con:  

```bash
cat sites/default/settings.php | grep -i 'db'
```

Este comando nos mostrará las líneas relacionadas con la configuración de la base de datos, incluyendo:  
- **Usuario de la base de datos**  
- **Contraseña**  
- **Host y nombre de la base de datos**  
