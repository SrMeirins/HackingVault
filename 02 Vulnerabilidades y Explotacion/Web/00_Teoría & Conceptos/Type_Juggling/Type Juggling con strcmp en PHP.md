# **Vulnerabilidad: Type Juggling en PHP con strcmp()**

Esta vulnerabilidad, conocida como **Type Juggling**, ocurre cuando un programa compara dos variables de tipos diferentes de una manera insegura. En PHP, esto es especialmente común cuando se utiliza la comparación débil (`==`) con funciones que pueden devolver resultados inesperados, como `strcmp()`.

### **1. Código Vulnerable**

El siguiente fragmento de código PHP es un ejemplo clásico de un formulario de inicio de sesión vulnerable a este ataque:

```php
<?php
session_start();

if (!empty($_POST['username']) && !empty($_POST['password'])) {
    require('config.php'); // Suponemos que aquí se definen $username y $password
    if (strcmp($username, $_POST['username']) == 0) {
        if (strcmp($password, $_POST['password']) == 0) {
            $_SESSION['user_id'] = 1;
            header("Location: /upload.php");
        } else {
            print("<script>alert('Wrong Username or Password')</script>");
        }
    } else {
        print("<script>alert('Wrong Username or Password')</script>");
    }
}
?>
```

-----

### **2. Análisis de la Vulnerabilidad**

El fallo de seguridad se encuentra en esta línea específica:

```php
if (strcmp($password, $_POST['password']) == 0) { ... }
```

Para entender por qué es vulnerable, debemos analizar tres puntos clave:

1.  **La función `strcmp()`**: Esta función está diseñada para comparar dos **cadenas de texto (strings)** de manera segura y sensible a mayúsculas y minúsculas.

      * Devuelve `0` si las dos cadenas son idénticas.
      * Devuelve un número `< 0` si la primera cadena es menor que la segunda.
      * Devuelve un número `> 0` si la primera cadena es mayor que la segunda.

2.  **El comportamiento inesperado de `strcmp()` con arrays**: Aquí radica el problema. En versiones de PHP anteriores a 8.0, si se pasa un **array** como uno de los argumentos a `strcmp()` en lugar de un string, la función no puede realizar la comparación. En lugar de fallar de forma segura, **devuelve `NULL`** y genera una advertencia (que a menudo está oculta en los servidores de producción).

3.  **La comparación débil (`==`)**: El código utiliza el operador de comparación débil (`==`) para verificar si el resultado de `strcmp()` es `0`.

      * En PHP, cuando se compara `NULL` con `0` usando `==`, el resultado es **`true`**. Es decir, la expresión `NULL == 0` es **VERDADERA**.

**Uniendo todo:** Un atacante puede explotar esto enviando un **array vacío** como valor para el parámetro `password`.

-----

### **3. Flujo y Explotación del Ataque**

El objetivo del atacante es hacer que `$_POST['password']` sea un array para que la comparación de la contraseña siempre sea exitosa.

**Pasos para el bypass:**

1.  **Conocer el nombre de usuario**: El atacante debe proporcionar un nombre de usuario válido, ya que la primera comparación `strcmp($username, $_POST['username'])` debe ser exitosa. Supongamos que el nombre de usuario es `admin`.

2.  **Enviar la contraseña como un array**: En una petición HTTP POST, esto se logra añadiendo corchetes `[]` al final del nombre del parámetro.

**Payload de explotación:**

Un atacante usaría una herramienta como `curl` o un proxy como Burp Suite para enviar la siguiente petición POST:

```http
POST /login/login.php HTTP/1.1
Host: 10.129.95.184
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

username=admin&password[]=
```

**¿Qué sucede en el servidor?**

1.  PHP recibe el parámetro `password[]=` y lo interpreta como un array vacío: `$_POST['password'] = []`.
2.  La línea vulnerable ejecuta `strcmp($password, [])`.
3.  La función `strcmp` recibe un string y un array, por lo que devuelve `NULL`.
4.  La condición se evalúa como `if (NULL == 0)`, lo cual es `true`.
5.  ¡Bypass exitoso\! El servidor concede el acceso y redirige al atacante a `/upload.php`.

-----

### **4. Cómo Mitigar la Vulnerabilidad**

Existen varias formas efectivas de corregir este fallo:

✅ **Opción 1: Usar Comparación Estricta (`===`)**

La solución más simple es cambiar el operador de comparación por uno estricto (`===`), que también comprueba que los tipos de datos sean iguales.

  * `NULL == 0`  es `true`.
  * `NULL === 0` es `false` (porque `NULL` no es del mismo tipo que el entero `0`).

**Código Corregido:**

```php
if (strcmp($password, $_POST['password']) === 0) { // ...
```

✅ **Opción 2: Validar el Tipo de Dato**

Asegúrate de que la entrada recibida es del tipo esperado (un string) antes de procesarla.

**Código Corregido:**

```php
if (is_string($_POST['password'])) {
    if (strcmp($password, $_POST['password']) == 0) {
        // ...
    }
}
```

✅ **Opción 3 (Mejor Práctica): Usar Funciones de Hashing**

La forma moderna y correcta de manejar contraseñas es **nunca** almacenarlas ni compararlas en texto plano. Se deben usar las funciones `password_hash()` y `password_verify()`.

**Código Correcto:**

```php
// Almacenar el hash en config.php (ej: $hashed_password)
// ...
if (password_verify($_POST['password'], $hashed_password)) {
    // Contraseña correcta
    $_SESSION['user_id'] = 1;
    header("Location: /upload.php");
}
```

Estas funciones están diseñadas para ser seguras y evitan por completo las vulnerabilidades de "Type Juggling".
