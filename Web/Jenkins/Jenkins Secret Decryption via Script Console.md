**Jenkins Secret Decryption via Script Console**

🚨 **Este ataque permite descifrar credenciales almacenadas en Jenkins si se tiene acceso a la consola de scripts.** 🚨

Cuando tenemos permisos de administrador en Jenkins y acceso a la consola de scripts, es posible obtener credenciales cifradas almacenadas en el servidor. Esto se puede hacer mediante el uso del inspector de código del navegador y la propia consola de Jenkins, la cual nos permitirá descifrar las credenciales y obtenerlas en texto claro.

**Procedimiento:**

1. **Acceder a la sección de credenciales**: Lo primero es acceder al panel de credenciales dentro de Jenkins y seleccionar una credencial que queramos descifrar. En este ejemplo, se utilizará una clave privada de SSH almacenada en Jenkins.

2. **Inspeccionar el código en el navegador**: A continuación, se debe hacer un "update" de la credencial seleccionada. Al actualizarla, podremos ver el valor cifrado en el código fuente de la página utilizando el inspector de código del navegador (generalmente con la tecla F12). En este caso, la clave privada SSH estará cifrada y la encontraremos en el campo correspondiente.

3. **Descifrar el valor con la consola de Jenkins**: Copiamos el valor cifrado y lo pegamos en la consola de scripts de Jenkins, donde utilizaremos la siguiente función para descifrarlo:
   ```groovy
   println hudson.util.Secret.decrypt("{value}")
   ```

   Al ejecutar este script, Jenkins nos devolverá la credencial descifrada en texto claro.

**Nota importante**: Este ataque solo es posible si se tiene acceso administrativo a Jenkins, ya que la consola de scripts es una herramienta poderosa que permite ejecutar comandos directamente en el servidor.
