# **Introducción a File Inclusion (Pentesting)**

Muchas aplicaciones web modernas (PHP, NodeJS, Java, .NET…) generan contenido dinámico usando parámetros HTTP para decidir qué recurso cargar en la página. Cuando esa lógica no se implementa de forma segura, un atacante puede manipular dichos parámetros para forzar que el servidor cargue archivos locales. Esto da lugar a la vulnerabilidad conocida como **Local File Inclusion (LFI)**.

## **¿Qué es LFI y por qué ocurre?**

En muchas aplicaciones se utilizan **motores de plantillas** para mantener una estructura común (header, menú, footer) y cargar dinámicamente solo el contenido variable. Por ejemplo:

```
/index.php?page=about
```

Si el valor de `page` se utiliza directamente para incluir un archivo (ej. `about.php`), un atacante puede reemplazarlo por rutas arbitrarias y conseguir que el servidor muestre **cualquier archivo local**.

## **Impacto de LFI**

Un LFI permite:

- **Divulgación de código fuente** → Facilita encontrar otras vulnerabilidades.
    
- **Exposición de información sensible** → Credenciales, claves API, rutas internas, archivos del sistema.
    
- **Ejecución remota de código (RCE)** en escenarios concretos (log poisoning, wrappers, sesiones, etc.).
    
- **Compromiso total del servidor** si se combina con otras debilidades.
    

Incluso si “solo” se lee el código fuente, esto puede permitir una escalada posterior.

---

# **Por qué aparece LFI en múltiples tecnologías**

Todas las plataformas suelen tener funciones para **cargar archivos dinámicamente** basándose en la entrada del usuario. Si esa entrada no se valida, se abre la puerta a LFI.

Ejemplos típicos:

### **PHP**

Funciones vulnerables si reciben parámetros sin validar:

- `include()`, `include_once()`
    
- `require()`, `require_once()`
    
- `file_get_contents()`
    
- `fopen()`, `file()`
    

Ejemplo vulnerable:

```php
include($_GET['language']);
```

### **NodeJS**

Lectura de archivos controlada por parámetros:

```js
fs.readFile(path.join(__dirname, req.query.language), ...)
```

O carga de plantillas en Express:

```js
res.render(`/${req.params.language}/about.html`);
```

### **Java (JSP)**

Incluye o importa archivos a partir de parámetros:

```jsp
<jsp:include file="<%= request.getParameter('language') %>" />
```

### **.NET**

Cargar contenido dinámico:

```cs
Response.WriteFile(Request.Query["language"]);
```

O incluso includes ejecutables:

```cs
<!--#include file="<% HttpContext.Request.Query['language'] %>"-->
```

---

# **Leer vs Ejecutar: diferencia clave en Pentesting**

No todas las funciones solo leen archivos; algunas también **ejecutan código** o cargan **URLs remotas**. Esto afecta directamente al impacto.

|Tecnología|Función|Lee|Ejecuta|URL remota|
|---|---|---|---|---|
|PHP|include()|✔️|✔️|✔️|
|PHP|require()|✔️|✔️|❌|
|PHP|file_get_contents()|✔️|❌|✔️|
|NodeJS|fs.readFile()|✔️|❌|❌|
|NodeJS|res.render()|✔️|✔️|❌|
|Java|import|✔️|✔️|✔️|
|.NET|include|✔️|✔️|✔️|

Esto es importante porque:

- Si la función **ejecuta**, el LFI puede convertirse en **RCE**.
    
- Si solo **lee**, permite **filtrar archivos**, con potencial exposición crítica.
    

---

# **Conclusión**

Las vulnerabilidades de File Inclusion aparecen en prácticamente cualquier stack porque el mecanismo de cargar archivos dinámicos es común. Para pentesters, LFI es una vulnerabilidad **crítica**, capaz de:

- revelar información sensible,
    
- exponer el código interno,
    
- facilitar enumeraciones avanzadas,
    
- y, en condiciones adecuadas, escalar a **ejecución remota de código** y toma total del servidor.
    

Incluso un LFI que solo permite lectura puede ser suficiente para comprometer la aplicación completa.