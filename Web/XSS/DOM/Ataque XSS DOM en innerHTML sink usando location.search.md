# Ataque XSS DOM en innerHTML sink usando location.search

Este ataque se produce cuando una aplicación web inserta datos controlados por el usuario directamente en el DOM sin una validación o sanitización adecuada. En este caso, el parámetro `search` se extrae de la URL y se inserta en el contenido HTML usando la propiedad `innerHTML`. Esto permite que un atacante inyecte código malicioso que se ejecutará en el navegador de la víctima.

---

## Ejemplo del Código Vulnerable

Imagina que tienes una barra de búsqueda y, tras realizar una consulta, el término buscado aparece en la URL y en la página de resultados. El código relevante es el siguiente:

```html
<h1>
  <span>2 search results for '</span>
  <span id="searchMessage"></span>
  <span>'</span>
</h1>
<script>
    function doSearchQuery(query) {
        document.getElementById('searchMessage').innerHTML = query;
    }
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query) {
        doSearchQuery(query);
    }
</script>
```

---

## Análisis Detallado del Código

### 1. Estructura HTML

- **`<h1>` y `<span>`:**
  - **`<h1>`:** Es el encabezado principal de la sección, utilizado aquí para mostrar un mensaje sobre los resultados de la búsqueda.
  - **Primer `<span>`:** Contiene el texto fijo: `"2 search results for '"`.
  - **Segundo `<span id="searchMessage">`:** Este elemento es el destino dinámico donde se insertará el término de búsqueda. Su `id` permite acceder a él desde JavaScript.
  - **Tercer `<span>`:** Contiene el carácter `'` de cierre, completando el mensaje del encabezado.

- **`<script>`:**
  - El bloque `<script>` contiene el código JavaScript que se encarga de extraer el término de búsqueda de la URL y actualizar el contenido del `<span id="searchMessage">`.

### 2. Bloque de JavaScript

- **Extracción del parámetro de la URL:**
  ```javascript
  var query = (new URLSearchParams(window.location.search)).get('search');
  ```
  - **`window.location.search`:** Obtiene la cadena de consulta de la URL, es decir, todo lo que sigue al signo `?` (por ejemplo, `"?search=hola"`).
  - **`URLSearchParams`:** Se utiliza para convertir la cadena de consulta en un objeto que permite acceder a cada parámetro de forma sencilla.
  - **`.get('search')`:** Extrae el valor del parámetro `search`. Por ejemplo, si la URL es `https://ejemplo.com/?search=hola`, el valor de `query` será `"hola"`.

- **Verificación y llamada a la función:**
  ```javascript
  if(query) {
      doSearchQuery(query);
  }
  ```
  - Se verifica si `query` tiene algún valor. Si es así, se invoca la función `doSearchQuery` pasando el valor extraído.

- **Función `doSearchQuery(query)`:**
  ```javascript
  function doSearchQuery(query) {
      document.getElementById('searchMessage').innerHTML = query;
  }
  ```
  - **`document.getElementById('searchMessage')`:** Busca el elemento con `id="searchMessage"` en el DOM.
  - **`innerHTML = query`:** Inserta el contenido de `query` dentro de este elemento. Como se usa `innerHTML`, cualquier cadena asignada se interpreta como HTML, lo que puede ser peligroso si el contenido no es seguro.

---

## ¿Por Qué Podemos Inyectar Código Malicioso?

El ataque XSS DOM en este caso se debe a que:

1. **Datos Controlados por el Usuario:**
   - El valor de `query` se extrae directamente de la URL. Esto significa que un atacante puede manipular este valor modificando la URL.

2. **Uso Inseguro de `innerHTML`:**
   - Al asignar el valor de `query` a `innerHTML`, el navegador interpreta el contenido como HTML. Esto permite que si el valor contiene etiquetas o scripts, éstos se ejecuten en el contexto de la página.

3. **Falta de Validación/Sanitización:**
   - No se realiza ninguna validación ni sanitización del valor de `query` antes de insertarlo en el DOM, lo que abre la puerta a inyecciones maliciosas.

---

## Ejemplo de Inyección Maliciosa

Considera la siguiente URL maliciosa:

```
https://0a9e00f004e039be807930e4001f00f7.web-security-academy.net/?search=%3Cimg%20src=x%20onerror=alert(%22Hacked%22)%3E
```

### ¿Qué sucede al decodificar el parámetro?

El valor del parámetro `search` se decodifica a:

```html
<img src=x onerror=alert("Hacked")>
```

### Cómo se Produce el Ataque

1. **Inserción en el DOM:**
   - La función `doSearchQuery(query)` inserta este contenido en el elemento `<span id="searchMessage">` usando `innerHTML`.

2. **Interpretación del Código Inyectado:**
   - El navegador interpreta el contenido y crea un elemento `<img>` con `src="x"`.
   - Debido a que `"x"` no es una URL válida, la carga de la imagen falla.

3. **Ejecución del Código Malicioso:**
   - Al fallar la carga, se dispara el evento `onerror` del `<img>`, que ejecuta `alert("Hacked")`. Esto demuestra que se ha inyectado y ejecutado código JavaScript arbitrario.

---

## Conclusiones y Medidas de Mitigación

- **Vulnerabilidad DOM XSS:**
  - El ataque se clasifica como XSS basado en DOM porque la inyección y ejecución del código malicioso ocurren completamente en el lado del cliente, al manipular el DOM con datos no sanitizados.

- **Riesgo de Usar `innerHTML`:**
  - `innerHTML` interpreta cualquier cadena como código HTML, lo que facilita la inyección de scripts si no se validan adecuadamente los datos.

- **Buenas Prácticas de Seguridad:**
  - **Validar y Sanitizar la Entrada:** Antes de insertar datos en el DOM, verifica y limpia el contenido recibido.
  - **Utilizar `textContent`:** Si solo necesitas mostrar texto, usa `textContent` para evitar la interpretación de HTML.
  - **Codificar la Entrada:** Utiliza funciones como `encodeURIComponent()` para codificar los datos y evitar que se interpreten como código.
