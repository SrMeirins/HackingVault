# Ataque Stored XSS en atributo href de anchor con comillas dobles HTML-encoded

Este ataque se produce cuando la aplicación almacena datos proporcionados por el usuario (por ejemplo, en una sección de comentarios) y luego los muestra en la página sin un filtrado o sanitización adecuados. En este escenario, el valor proporcionado por el usuario se refleja en el atributo `href` de un enlace (`<a>`), y aunque los caracteres de ángulo se codifican para prevenir la inyección de etiquetas HTML, es posible explotar la vulnerabilidad inyectando una URL con el esquema `javascript:`. Esto permite la ejecución de código JavaScript cuando el usuario interactúa con el enlace.

---

## Ejemplo del Código Vulnerable

Supongamos que tenemos una sección de comentarios en la que el usuario puede dejar su nombre, comentario, correo electrónico y sitio web. La entrada del campo "website" se utiliza para generar un enlace que apunta a la URL indicada. Por ejemplo, al enviar los siguientes parámetros:

```
csrf=aKxRt7CY8YvQK5JX5k1LWP5RZrOiZ8Tx&postId=1&comment=test&name=test&email=test%40test.com&website=web
```

El HTML generado podría ser:

```html
<p>
  <img src="/resources/images/avatarDefault.svg" class="avatar">
  <a id="author" href="web">test</a> | 16 February 2025
</p>
```

La URL reflejada (en el atributo `href`) es la que introdujo el usuario (en este caso, "web").

---

## Explicación Detallada del Ataque

### 1. Reflejo de la Entrada del Usuario

- **Almacenamiento y Visualización:**
  - La aplicación almacena el valor del parámetro `website` junto con el resto de la información del comentario.
  - Cuando se muestran los comentarios, el valor del campo `website` se inserta dentro del atributo `href` del elemento `<a>`.

- **HTML Resultante con Valor Seguro:**
  - Con una entrada normal, por ejemplo, `website=web`, el HTML se renderiza así:
    ```html
    <a id="author" href="web">test</a>
    ```
  - Los caracteres especiales, como los ángulos, se codifican (HTML-encoded), evitando que se interpreten como parte de una etiqueta.

### 2. Limitaciones y Oportunidad para la Inyección

- **Protección Inicial:**
  - La codificación HTML protege contra inyecciones que usan etiquetas completas (por ejemplo, `<script>` se codifica a `&lt;script&gt;`).

- **Explotación Mediante Cambio de Contexto:**
  - En atributos `href`, no se interpretan etiquetas HTML, pero es posible cambiar el esquema de la URL.
  - Al inyectar un valor que inicie con `javascript:`, se crea un enlace que, al ser clicado, ejecuta código JavaScript.

### 3. Payload Malicioso y su Funcionamiento

- **Payload de Inyección:**
  - Se envía el siguiente valor en el parámetro `website`:
    ```
    javascript:alert(1)
    ```
  - Este valor debe ser debidamente codificado en la URL (por ejemplo, `javascript%3Aalert%281%29`), pero al decodificarse en el servidor, se almacena como `javascript:alert(1)`.

- **HTML Resultante con Payload:**
  - La salida HTML será:
    ```html
    <a id="author" href="javascript:alert(1)">test</a>
    ```
  - En este caso, aunque se codificaron los ángulos y otros caracteres, el cambio de esquema no es impedido.

- **Mecanismo de Ejecución:**
  - Los navegadores permiten enlaces con el esquema `javascript:`, lo que significa que al hacer clic en el enlace, se ejecutará el código JavaScript contenido en el atributo `href`.
  - En este ejemplo, se ejecuta `alert(1)` al interactuar con el enlace, lo que demuestra la explotación del Stored XSS.

### 4. Por Qué Funciona

- **Stored XSS:**
  - La inyección se almacena en la base de datos junto con el comentario y se refleja cada vez que se carga la página de comentarios.
  - Esto permite que todos los usuarios que visualicen el comentario vean el enlace malicioso.

- **HTML-Encoding Parcial:**
  - Aunque se realiza HTML-encoding para proteger contra la inserción de etiquetas HTML, no se impide la manipulación del contenido del atributo `href` cuando se cambia el esquema a `javascript:`.

- **Limitación en Atributos href:**
  - En atributos `href`, las etiquetas HTML no son interpretadas; sin embargo, los esquemas de URL como `javascript:` pueden provocar la ejecución de código si no se validan adecuadamente.

---

## Conclusiones y Medidas de Mitigación

- **Naturaleza del Ataque:**
  - Se trata de un ataque Stored XSS, ya que el payload malicioso se almacena en la aplicación (por ejemplo, en la base de datos de comentarios) y se refleja en cada carga de la página.
  - La vulnerabilidad se origina al no validar ni sanitizar adecuadamente la entrada del usuario antes de incluirla en el atributo `href` de un enlace.

- **Medidas de Mitigación:**
  1. **Validar y Sanitizar la Entrada:**
     - Verificar y limpiar el valor recibido en el campo `website` para asegurarse de que solo se permitan URLs legítimas.
  2. **Restricción de Esquemas Permitidos:**
     - Implementar una lista blanca de esquemas (por ejemplo, solo `http` y `https`) para evitar la ejecución de URLs con `javascript:`.
  3. **Codificación de Salida:**
     - Aunque se esté usando HTML-encoding, se debe aplicar una validación adicional en el contexto del atributo para evitar cambios de esquema.
  4. **Uso de APIs o Funciones de Escape Específicas:**
     - Utilizar funciones de escape que aseguren que los datos se inserten de forma segura en atributos HTML.
