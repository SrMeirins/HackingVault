# **Ejecución Remota de Código en Drupal con PHP Filter (Necesario acceso como ADMIN)**  

> **⚠️ ¡Es imprescindible tener privilegios como ADMIN en Drupal para realizar este ataque!**  
> Tener acceso como administrador es fundamental para habilitar el módulo **PHP Filter** y ejecutar código PHP arbitrario en el servidor.

Cuando tenemos acceso al panel de administración de Drupal con privilegios de **ADMIN**, podemos habilitar el módulo **PHP Filter** para ejecutar código PHP arbitrario en el servidor. Este tipo de ataque es útil para obtener acceso adicional o ejecutar comandos en el servidor de manera remota.  

---

## **Pasos para ejecutar el ataque**  

1. **Acceder al Panel de Administración**:  
   Una vez dentro de Drupal como ADMIN, nos dirigimos a la sección **Modules** y habilitamos el módulo **PHP Filter**.  
   
2. **Crear un Nuevo Artículo**:  
   Vamos a **Content → Add Content → Article** y en el campo PHP, podemos inyectar un **reverse shell** o cualquier otro código malicioso que desee ejecutarse.  
   
3. **Testear el Comando**:  
   Como prueba inicial, podemos correr un comando básico y visualizar el output al previsualizar el artículo, asegurándonos de que el código PHP se ejecute correctamente.  
   
4. **Verificar Configuración**:  
   Es importante asegurarnos de que la entrada de código PHP esté habilitada correctamente en los artículos, para lo cual debemos verificar la configuración de entrada de código.  
