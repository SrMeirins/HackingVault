# Reflect XSS en una Cadena JavaScript con Ángulos HTML-Encoded

Este ataque se produce cuando datos controlados por el usuario se reflejan dentro de un literal (cadena) en el código JavaScript. Aunque los caracteres de ángulo se codifican en la salida HTML para evitar la inyección directa de etiquetas, la vulnerabilidad surge por cómo se construye la cadena en el código JavaScript, permitiendo romper su estructura e inyectar código malicioso.

---

## Ejemplo del Código Vulnerable

Imagina una página web con un formulario de búsqueda que, además de mostrar resultados, utiliza el término de búsqueda para generar una imagen de seguimiento. El código vulnerable es el siguiente:

```html
<section class="blog-header">
    <h1>0 search results for 'test'</h1>
    <hr>
</section>
<section class="search">
    <form action="/" method="GET">
        <input type="text" placeholder="Search the blog..." name="search">
        <button type="submit" class="button">Search</button>
    </form>
</section>
<script>
    var searchTerms = 'test';
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + encodeURIComponent(searchTerms) + '">');
</script>
```

En condiciones normales, con `search=test`, la variable `searchTerms` contiene la cadena `'test'` y se inserta de forma segura en la URL del `<img>`.

---

## ¿Qué es una Cadena en JavaScript?

En JavaScript, una **cadena** es un tipo de dato que representa una secuencia de caracteres. Se define típicamente entre comillas simples (`'...'`) o comillas dobles (`"..."`). Por ejemplo:
- `'test'`
- `"hola"`

Estas cadenas se usan para representar textos y pueden combinarse mediante concatenación. Cuando un desarrollador construye código concatenando variables con literales (como en nuestro ejemplo usando el operador `+`), es crucial asegurarse de que la estructura de la cadena no pueda ser rota por datos maliciosos.

---

## El Problema: Inyección en el Literal de la Cadena

En el código vulnerable, la variable `searchTerms` se define en un literal de cadena:
```javascript
var searchTerms = 'test';
```
Luego se utiliza en una concatenación para formar una parte de un fragmento HTML que se inserta en la página:
```javascript
document.write('<img src="/resources/images/tracker.gif?searchTerms=' + encodeURIComponent(searchTerms) + '">');
```
El problema surge cuando un atacante logra inyectar contenido malicioso en `searchTerms`. Si el atacante puede manipular el valor de `searchTerms`, puede romper la delimitación de la cadena, forzando la ejecución de código JavaScript arbitrario.

---

## Explicación Paso a Paso de la Inyección

### Payload Ejemplo: 
```
'+alert("Hacked")+'
```

1. **Definición Original del Literal:**
   - El código original define la variable de la siguiente forma:
     ```javascript
     var searchTerms = 'test';
     ```
   - Los delimitadores son las comillas simples que indican el inicio y el fin de la cadena.

2. **Inyección del Payload:**
   - Si un atacante inyecta el payload `'+alert("Hacked")+'` en lugar de `test`, la definición se convierte en:
     ```javascript
     var searchTerms = ''+alert("Hacked")+'';
     ```
   - **Ruptura del Literal:**
     - El primer conjunto de comillas simples se cierra inmediatamente: `''` representa una cadena vacía.
     - El operador `+` a continuación permite concatenar la evaluación de la función `alert("Hacked")`.
     - Luego, se abre una nueva cadena vacía con `''`.

3. **Evaluación del Código Inyectado:**
   - Durante la ejecución, JavaScript evalúa la expresión:
     ```javascript
     '' + alert("Hacked") + ''
     ```
   - La función `alert("Hacked")` se ejecuta inmediatamente. El valor que retorne (normalmente `undefined`) se convierte en parte de la cadena.
   - Aunque el resultado final de la cadena pueda ser "incorrecto" (por ejemplo, `"undefined"`), el daño se produce en el momento de la ejecución del `alert("Hacked")`.

4. **Construcción del HTML:**
   - Después de la inyección, se invoca:
     ```javascript
     document.write('<img src="/resources/images/tracker.gif?searchTerms=' + encodeURIComponent(searchTerms) + '">');
     ```
   - Pero ya habiendo ejecutado el payload, la alerta se dispara, demostrando la vulnerabilidad XSS.

---

## Otros Payloads que Funcionan

### Payload: 
```
'-alert("Hacked")-'
```
- **¿Por qué funciona?**
  - Si el atacante inyecta `'-alert("Hacked")-'`, el literal se convierte en:
    ```javascript
    var searchTerms = '-alert("Hacked")-';
    ```
  - Dependiendo de cómo se use la variable, es posible que la inyección se procese de forma similar. En ciertos contextos, si se concatenan o evalúan operaciones sobre esta cadena, el atacante podría manipular la lógica.  
  - **Nota:** Este payload puede funcionar si el código que procesa la variable realiza operaciones que permiten la inyección de código, o si se combina con otros vectores de inyección. Sin embargo, su efectividad depende del contexto exacto en que se use la cadena.

### Payload: 
```
';alert("Hacked");'
```
- **¿Por qué funciona?**
  - Con este payload, la variable se definiría como:
    ```javascript
    var searchTerms = '';alert("Hacked");'';
    ```
  - En este caso:
    - La cadena se cierra con la primera comilla (`''`).
    - Luego, se inyecta el código `;alert("Hacked");` fuera del literal de la cadena.
    - Finalmente, se vuelve a abrir un literal vacío.
  - Esto efectivamente separa la inyección del valor esperado, haciendo que el código malicioso se ejecute como una instrucción independiente en el flujo del script.

---

## Conclusiones y Medidas de Mitigación

- **Separación de Datos y Código:**
  - Es fundamental evitar la concatenación directa de datos no confiables en literales de cadena que formen código JavaScript.  
  - Usar plantillas seguras o funciones que automaticen el escape de caracteres es una buena práctica.

- **Validación y Sanitización:**
  - Valida y sanitiza siempre la entrada del usuario antes de utilizarla en cualquier contexto, especialmente en cadenas que se evaluarán como parte del código JavaScript.

- **Uso de APIs Seguras:**
  - Emplear métodos que permitan insertar datos de forma segura en el DOM sin necesidad de construir cadenas de código manualmente.
