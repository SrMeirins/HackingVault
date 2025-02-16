# Ataque Reflected XSS en Atributo con Ángulos HTML-Encoded

Este ataque ocurre cuando una aplicación web refleja datos controlados por el usuario en un atributo HTML (en este caso, el atributo `value` de un campo `<input>`). Aunque los caracteres de ángulo se codifican para evitar la interpretación de etiquetas HTML, es posible romper la estructura del atributo y añadir código malicioso, explotando la forma en que se genera el HTML.

---

## Ejemplo del Código Vulnerable

La aplicación tiene una barra de búsqueda que refleja el término ingresado en dos lugares:

1. **Campo de búsqueda (input):**
   ```html
   <input type="text" placeholder="Search the blog..." name="search" value="test">
   ```
   - El valor del atributo `value` es controlado por el parámetro `search` (por ejemplo, `?search=test`).

2. **Encabezado que muestra los resultados:**
   ```html
   <h1>0 search results for 'test'</h1>
   ```

Si se intenta inyectar, por ejemplo, `<script></script>`, los caracteres de ángulo son HTML-encoded (por ejemplo, `<` se convierte en `&lt;`), por lo que el navegador no interpretará la etiqueta. Sin embargo, podemos explotar la inyección modificando la forma en que el dato se inserta en el atributo.

---

## Explicación Detallada del Ataque

### 1. Reflejo de la Entrada del Usuario

- **Campo `<input>`:**
  - El campo de búsqueda se genera dinámicamente usando el valor del parámetro `search`. Por ejemplo, con `?search=test`, el HTML resultante es:
    ```html
    <input type="text" placeholder="Search the blog..." name="search" value="test">
    ```
  - Este valor se inserta entre comillas dobles en el atributo `value`.

- **Encabezado `<h1>`:**
  - La búsqueda también se refleja en el contenido del encabezado:
    ```html
    <h1>0 search results for 'test'</h1>
    ```

### 2. Protección Inicial y su Limitación

- La aplicación codifica los caracteres de ángulo, lo que impide que etiquetas completas como `<script>` se ejecuten.
- Sin embargo, la vulnerabilidad radica en cómo se inserta el valor dentro de un atributo delimitado por comillas dobles. Si se logra romper esta delimitación, es posible inyectar nuevos atributos o eventos.

### 3. Rompiendo la Estructura del Atributo

- **La Técnica de Inyección:**
  - Se inyecta el siguiente payload:
    ```
    " onmouseover="alert(1)
    ```
  - Este payload se utiliza en el parámetro `search`, y al reflejarse en el HTML, modifica la estructura del elemento.

- **Resultado de la Inyección:**
  - El HTML modificado se ve así:
    ```html
    <input type="text" placeholder="Search the blog..." name="search" value="" onmouseover="alert(1)">
    ```
  - **Explicación del Payload:**
    1. **Cierre Prematuro del Atributo `value`:**
       - El primer carácter (`"`) cierra el atributo `value`. En lugar de tener `value="test"`, ahora queda `value=""`.
    2. **Inserción del Nuevo Atributo:**
       - La cadena ` onmouseover="alert(1)` se interpreta como un nuevo atributo en el elemento `<input>`, añadiendo un manejador de eventos.
    3. **Ejecución del Código Malicioso:**
       - Cuando el usuario pase el cursor sobre el campo de búsqueda, se dispara el evento `onmouseover` que ejecuta `alert(1)`.

- **Reflejo en el Encabezado:**
  - El mismo payload también se refleja en el encabezado, lo que puede verse así:
    ```html
    <h1>0 search results for '" onmouseover="alert(1)'</h1>
    ```
  - Aunque en este caso el impacto visual es menor, confirma que el payload se inyectó en la respuesta.

---

## Conclusiones y Medidas de Mitigación

- **Naturaleza del Ataque:**
  - Se trata de un ataque XSS reflejado, donde la entrada del usuario se refleja inmediatamente en la respuesta sin una validación adecuada.
  - Aunque los caracteres de ángulo son codificados para evitar la ejecución de etiquetas HTML, el atacante explota la inyección al romper la estructura de los atributos.

- **Medidas de Mitigación:**
  1. **Validar y Sanitizar la Entrada:**
     - Limpiar y validar cualquier dato que se vaya a insertar en atributos HTML, evitando que se pueda cerrar la delimitación prematuramente.
  2. **Codificación Segura:**
     - Aplicar una codificación que asegure no solo la transformación de los ángulos, sino también la protección de las comillas y otros caracteres críticos.
  3. **Uso de APIs Seguras:**
     - Emplear métodos o librerías que gestionen el escape de datos de forma apropiada en el contexto HTML y de atributos.
