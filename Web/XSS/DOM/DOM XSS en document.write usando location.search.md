# DOM XSS en document.write usando location.search

## Introducción
El ataque de Cross-Site Scripting (XSS) basado en DOM ocurre cuando la manipulación del Document Object Model (DOM) permite la ejecución de código malicioso en el navegador de la víctima. Este tipo de vulnerabilidad no se refleja en el HTML enviado por el servidor, sino que se genera dinámicamente en el lado del cliente mediante JavaScript.

Uno de los métodos comunes en el que ocurre este ataque es cuando una aplicación web utiliza `document.write` para insertar datos controlados por el usuario directamente en la página sin ninguna validación o sanitización. En este caso, la fuente del ataque es `location.search`, que permite modificar la URL para inyectar código malicioso.

---

## Explicación detallada del ataque
El siguiente código JavaScript representa una funcionalidad de rastreo de búsquedas en un sitio web. Toma el parámetro `search` de la URL y lo usa para generar una imagen de seguimiento en la página:

```html
<script>
    function trackSearch(query) {
        document.write('<img src="/resources/images/tracker.gif?searchTerms='+query+'">');
    }
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query) {
        trackSearch(query);
    }
</script>
```

### Análisis del código en profundidad
1. **Extracción del parámetro `search`**:
    - `window.location.search` obtiene la cadena de consulta de la URL, es decir, la parte después del `?`.
    - `new URLSearchParams(window.location.search)` convierte esta cadena en un objeto que permite acceder a los parámetros fácilmente.
    - `.get('search')` obtiene el valor del parámetro `search`, el cual puede ser controlado por un atacante al modificar la URL.

2. **Verificación de la existencia del parámetro**:
    - `if(query)` verifica si el parámetro `search` tiene algún valor.
    - Si `query` contiene datos, se llama a `trackSearch(query)`.

3. **Uso de `document.write` para insertar contenido dinámico**:
    - `document.write` se usa para escribir en el documento HTML.
    - La función `trackSearch(query)` genera una etiqueta `<img>` con un atributo `src` que contiene el valor del parámetro `query`.
    - Como `query` proviene directamente de la URL sin ser filtrado ni codificado, un atacante puede inyectar código malicioso manipulando el valor de `search` en la URL.

### Ejemplo de inyección maliciosa
Un atacante puede manipular la URL para inyectar código malicioso como el siguiente:

```
https://victima.com/?search="\><IMG SRC=x onerror="alert(1)">
```

#### Explicación del código malicioso por partes
1. `?search="\>`:
    - Se cierra prematuramente el atributo `src` del `<img>` original.
    - El `>` cierra la etiqueta `<img>` preexistente y permite inyectar una nueva.
    
2. `<IMG SRC=x onerror="alert(1)">`:
    - Se crea un nuevo elemento `<img>` con un `src` inválido (`x`).
    - El atributo `onerror` se ejecuta cuando el navegador no puede cargar la imagen (debido a la URL inválida).
    - `alert(1)` ejecuta una alerta, demostrando la ejecución de JavaScript arbitrario.

### Solución y mitigación
Para prevenir este tipo de ataques, es fundamental evitar el uso de `document.write` con datos no validados o sanitizados. Algunas estrategias para mitigar este riesgo incluyen:

1. **Evitar `document.write`**: Usar `textContent` o `innerText` en lugar de `innerHTML`.
2. **Validación y sanitización de entradas**: Asegurar que los datos introducidos por el usuario no contengan caracteres peligrosos como `<`, `>`, `"`, `'`, etc.
3. **Uso de bibliotecas seguras**: Implementar frameworks o bibliotecas que manejen de forma segura la manipulación del DOM.
4. **CSP (Content Security Policy)**: Configurar una política de seguridad de contenido que restrinja la ejecución de scripts no confiables.

### Código corregido
Una forma segura de implementar esta funcionalidad sería:

```html
<script>
    function trackSearch(query) {
        let img = document.createElement("img");
        img.src = "/resources/images/tracker.gif?searchTerms=" + encodeURIComponent(query);
        document.body.appendChild(img);
    }
    var query = (new URLSearchParams(window.location.search)).get('search');
    if(query) {
        trackSearch(query);
    }
</script>
```

Con esta solución:
- Se usa `encodeURIComponent()` para evitar la inyección de código malicioso.
- Se crea un nuevo elemento `<img>` en lugar de modificar directamente el HTML con `document.write`.
- Se inserta el elemento de forma segura en la página con `appendChild()`.

Siguiendo estas prácticas, se pueden prevenir ataques de DOM XSS y mejorar la seguridad de la aplicación web.

