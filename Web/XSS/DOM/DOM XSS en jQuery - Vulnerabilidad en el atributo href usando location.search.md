## **🔴 DOM XSS en jQuery - Vulnerabilidad en el atributo `href` usando `location.search`**

### **📝 Descripción**  
La vulnerabilidad **DOM XSS (Cross-Site Scripting)** ocurre cuando datos no confiables, como parámetros de la URL, se insertan directamente en el DOM (en este caso en el atributo `href` de un enlace) sin sanitización. Esto permite a un atacante inyectar y ejecutar código JavaScript malicioso en el navegador de un usuario.

En este caso:
- **Source**: Los parámetros de la URL, específicamente `window.location.search`, que pueden ser manipulados por un atacante para incluir datos maliciosos.
- **Sink**: El atributo `href` del enlace, donde se inserta directamente el valor de la URL sin validación, lo que permite la ejecución de código JavaScript cuando el usuario interactúa con el enlace.

---

## **🔍 Código Vulnerable**
```html
<div class="is-linkback">
    <a id="backLink">Back</a>
</div>
<script>
    $(function() {
        $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
    });
</script>
```

### **1️⃣ Desglosando el código**
1. **HTML del enlace (`<a>`):**
   - Se crea un enlace con el `id="backLink"`, pero **sin `href` definido inicialmente**. Este valor será actualizado más tarde por el script.
   ```html
   <a id="backLink">Back</a>
   ```

2. **JavaScript:**
   - `$(function() {...})`: Este es un **handler de jQuery** que espera a que el DOM esté listo para ejecutar el código. En este caso, cuando la página cargue, actualizará el `href` del enlace.
   ```javascript
   $(function() {
       $('#backLink').attr("href", (new URLSearchParams(window.location.search)).get('returnPath'));
   });
   ```

   - `window.location.search`: Obtiene los parámetros de la URL que están después del signo de interrogación (`?`). Por ejemplo, si la URL es:
     ```
     https://example.com/page?returnPath=/home
     ```
     `window.location.search` devolvería `?returnPath=/home`.

   - **`URLSearchParams(window.location.search).get('returnPath')`:**
     Extrae el valor del parámetro `returnPath` de la URL. En el ejemplo de arriba, sería `"/home"`.
   
   - Luego, el atributo `href` del enlace con `id="backLink"` se actualiza con el valor obtenido de `returnPath`:
     ```javascript
     $('#backLink').attr("href", returnPath);
     ```

   Si la URL es:
   ```
   https://example.com/page?returnPath=/home
   ```
   El resultado final en HTML será:
   ```html
   <a id="backLink" href="/home">Back</a>
   ```

---

## **⚠️ Vulnerabilidad: XSS mediante el atributo `href`**

### **¿Cómo se explota la vulnerabilidad?**
Un atacante puede modificar el parámetro `returnPath` en la URL para ejecutar código JavaScript malicioso. Por ejemplo:
```
https://example.com/page?returnPath=javascript:alert(document.cookie)
```
### **¿Qué sucede cuando se carga esta URL?**
1. **URL modificada:**
   - El parámetro `returnPath` se convierte en:
   ```javascript
   returnPath = "javascript:alert(document.cookie)"
   ```
   
2. **Modificación del enlace:**
   El código vulnerable asigna este valor directamente al atributo `href` del enlace:
   ```html
   <a id="backLink" href="javascript:alert(document.cookie)">Back</a>
   ```
   
3. **Ejecución al hacer clic:**
   Cuando el usuario hace clic en el enlace, el navegador **ejecutará el código JavaScript** contenido en el `href`, que es:
   ```javascript
   alert(document.cookie);
   ```
   Esto **muestra las cookies del navegador** (que pueden incluir información sensible como las cookies de sesión).

   **Resultado:**
   - **Robo de cookies**: Un atacante puede obtener cookies de sesión o datos confidenciales de la víctima.
   - **Ejecución de JavaScript malicioso**: El atacante podría robar información, realizar phishing o ejecutar cualquier código que pueda comprometer al usuario.

---

### **❓ ¿Por qué se usa `javascript:` en lugar de `<script>`?**

**Explicación de la diferencia:**

- **`<script>`**: Si quisieras inyectar un `<script>` en el HTML, tendrías que modificar el DOM, lo cual es difícil cuando solo estás manipulando el atributo `href` de un enlace. Los navegadores no ejecutan automáticamente los elementos `<script>` cuando están dentro de atributos como `href`. 

- **`javascript:`**: Cuando un enlace (`<a>`) tiene un `href` que comienza con `javascript:`, el navegador **ejecuta** el código JavaScript cuando el usuario hace clic en el enlace.  
  - **Ejemplo**:
    ```html
    <a href="javascript:alert('XSS')">Haz clic aquí</a>
    ```
    Al hacer clic, se ejecutará el código `alert('XSS')`.

Por lo tanto, un atacante puede aprovechar `javascript:` en lugar de `<script>` para **ejecutar JavaScript directamente** desde un atributo `href`.

---

## **🔐 Solución para evitar esta vulnerabilidad**

### **1. Validar y sanear los datos del parámetro `returnPath`**
Antes de insertar el valor de `returnPath` en el atributo `href`, es crucial validar que sea una URL interna segura. No debe contener esquemas peligrosos como `javascript:`.

#### **Código seguro**:
```javascript
$(function() {
    let returnPath = (new URLSearchParams(window.location.search)).get('returnPath');

    // Validar que returnPath sea una ruta interna válida
    if (returnPath && returnPath.startsWith("/") && !returnPath.includes("//")) {
        $('#backLink').attr("href", returnPath);
    } else {
        $('#backLink').attr("href", "/defaultPage"); // Página segura por defecto
    }
});
```

- **Qué se hace**:
  - **`returnPath.startsWith("/")`**: Asegura que el valor de `returnPath` comienza con `/`, lo que indica que es una ruta relativa dentro del mismo dominio.
  - **`!returnPath.includes("//")`**: Asegura que no contiene `//`, lo que evitaría que el atacante inyectara una URL externa.
  - Si la validación falla, se asigna un valor por defecto seguro (como `/defaultPage`).

### **2. Consideraciones adicionales**
- **Evitar `javascript:`**: No permitir que los enlaces tengan `href="javascript:"`, ya que es una vía común de explotación.
- **Sanitización de entrada**: Si se necesitan parámetros de la URL, siempre se deben sanitizar y validar antes de ser utilizados en el DOM.

---

## **🎯 Resumen final**

- **Código Vulnerable**: El código inserta sin validar datos desde la URL directamente en el atributo `href`, lo que permite ejecutar JavaScript malicioso.
- **Explotación**: Un atacante manipula el parámetro `returnPath` para incluir `javascript:alert(document.cookie)`, lo que permite ejecutar código malicioso cuando la víctima hace clic en el enlace.
- **¿Por qué `javascript:`?**: `javascript:` en `href` ejecuta código JavaScript directamente cuando el usuario hace clic, a diferencia de `<script>` que requiere modificar el DOM.
- **Solución**: Validar y sanear adecuadamente el valor de `returnPath` antes de insertarlo en el `href` para evitar que se inyecten esquemas maliciosos como `javascript:`.
