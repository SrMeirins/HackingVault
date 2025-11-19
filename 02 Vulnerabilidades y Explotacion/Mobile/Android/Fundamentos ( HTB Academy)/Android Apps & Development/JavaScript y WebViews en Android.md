Un **WebView** es un **componente de Android** que permite renderizar contenido web dentro de una aplicación. Se puede pensar como un **mini navegador dentro de la app**, capaz de mostrar HTML, CSS y ejecutar JavaScript.

Aunque útil, **su mal uso puede introducir vulnerabilidades graves**, como:

- **XSS (Cross-Site Scripting):** ejecución de scripts maliciosos.
    
- **LFI (Local File Inclusion):** inclusión de archivos locales no autorizados.
    
- **Exposición de APIs sensibles del sistema o la app.**
    

Por eso, la documentación oficial recomienda, siempre que sea posible, usar **el navegador del sistema** en lugar de WebViews, salvo que sea estrictamente necesario integrarlo en la app.

---

## **1) Layout XML básico – activity_main.xml**

```xml
<WebView
    android:id="@+id/webview"
    android:layout_width="match_parent"
    android:layout_height="match_parent" />
```

### Explicación línea por línea:

- `<WebView>`: define un **componente de tipo WebView**.
    
- `android:id="@+id/webview"`: asigna un **identificador único**, que permite referenciar este WebView desde Java o Kotlin. El prefijo `@+id/` indica que se crea un **nuevo recurso de ID**.
    
- `android:layout_width="match_parent"` y `android:layout_height="match_parent"`: el WebView ocupará todo el ancho y alto del contenedor padre (pantalla de la app).
    

---

## **2) MainActivity.java – Integración de WebView**

```java
package com.example.myapplication;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.webkit.WebView;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Obtenemos la referencia al WebView definido en XML
        WebView webview = (WebView) findViewById(R.id.webview);

        // Habilitamos la ejecución de JavaScript
        webview.getSettings().setJavaScriptEnabled(true);

        // Cargamos un archivo HTML local desde la carpeta assets
        webview.loadUrl("file:///android_asset/html/index.html");
    }
}
```

### Explicación línea por línea:

1. `WebView webview = (WebView) findViewById(R.id.webview);`
    
    - `findViewById(R.id.webview)` busca el componente WebView definido en XML.
        
    - `(WebView)` es un **casting**, que convierte el objeto genérico que devuelve `findViewById` en un **tipo WebView específico**.
        
    - Esto permite acceder a todos los métodos propios de WebView, como `loadUrl()` o `getSettings()`.
        
2. `webview.getSettings().setJavaScriptEnabled(true);`
    
    - Obtiene la configuración del WebView (`getSettings()`).
        
    - Activa la ejecución de **JavaScript** (`setJavaScriptEnabled(true)`).
        
    - ⚠️ Advertencia: **habilitar JavaScript en contenido externo puede ser peligroso** y exponer la app a XSS.
        
3. `webview.loadUrl("file:///android_asset/html/index.html");`
    
    - Carga el archivo `index.html` desde la carpeta **assets** dentro del proyecto.
        
    - La ruta `file:///android_asset/` es la forma estándar de acceder a archivos locales en Android.
        
    - Si quisiéramos cargar contenido web externo, cambiaríamos la URL por `https://www.google.com/`.
        

---

## **3) Estructura de archivos del proyecto**

```
app/
├─ src/main/assets/
│   ├─ html/index.html
│   ├─ css/style.css
│   └─ js/script.js
```

- **assets/** → carpeta donde se colocan archivos locales (HTML, CSS, JS).
    
- **html/** → archivos HTML.
    
- **css/** → estilos CSS.
    
- **js/** → scripts JavaScript.
    

---

## **4) index.html**

```html
<html>
<head>
    <link rel="stylesheet" href="../css/style.css">
    <script src="../js/script.js"></script>
</head>
<body>
<h1>
    <script>printMessage()</script>
</h1>
</body>
</html>
```

### Explicación:

- `<link rel="stylesheet" href="../css/style.css">` → enlaza el archivo CSS con los estilos de la página.
    
- `<script src="../js/script.js"></script>` → enlaza el archivo de JavaScript.
    
- `<script>printMessage()</script>` → llama a la función `printMessage()` del archivo JS.
    
- `<h1>` → etiqueta HTML que mostrará el contenido generado por la función de JavaScript.
    

---

## **5) script.js**

```javascript
function printMessage() {
    document.write("Hello from Javascript");
}
```

### Explicación línea por línea:

1. `function printMessage()` → define una **función** llamada `printMessage`.
    
2. `document.write("Hello from Javascript")` → escribe directamente en el **documento HTML** el texto `"Hello from Javascript"`.
    
    - `document` → representa el **DOM** (Document Object Model) de la página HTML.
        
    - `write()` → método que imprime contenido dentro del documento HTML actual.
        

Cuando el WebView carga el HTML, el texto **Hello from Javascript** aparece en pantalla.

---

## **6) Cargar contenido web externo**

```java
webview.loadUrl("https://www.google.com/");
```

- Cambia la URL para cargar contenido desde Internet.
    
- ⚠️ Requiere el permiso **INTERNET** en AndroidManifest.xml:
    

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

---

## **7) Seguridad y buenas prácticas**

- **No habilitar JavaScript si no es necesario.**
    
- Evitar cargar contenido externo de origen no confiable.
    
- Limitar acceso a archivos locales y APIs sensibles.
    
- Mantener actualizado el WebView y la app para evitar vulnerabilidades conocidas.
    

---

## **8) Flujo de ejecución paso a paso**

1. Android inicia la **MainActivity**.
    
2. Se carga el layout XML con el WebView.
    
3. Se obtiene la referencia del WebView en Java.
    
4. Se habilita JavaScript si se necesita.
    
5. Se carga la página local (`file:///`) o externa (`https://`).
    
6. El WebView renderiza HTML, aplica CSS y ejecuta JavaScript.
    
7. El contenido dinámico generado por JS se muestra en pantalla.
    

---

## **9) Conceptos clave para principiantes**

|Concepto|Explicación|
|---|---|
|WebView|Componente de Android para mostrar contenido web dentro de la app.|
|setJavaScriptEnabled(true)|Permite ejecutar código JavaScript. Puede ser riesgoso si se carga contenido externo.|
|Assets folder|Carpeta donde se colocan archivos locales (HTML, CSS, JS) accesibles por la app.|
|document.write()|Función de JavaScript que escribe contenido directamente en la página.|
|Casting|Conversión de un objeto de un tipo a otro (ej. `View` → `WebView`).|
|loadUrl|Método que indica qué página HTML o URL cargar dentro del WebView.|
|Permiso INTERNET|Requerido para que la app pueda acceder a URLs externas.|
|XSS / LFI|Vulnerabilidades comunes si se habilita JS sin control o se cargan archivos inseguros.|

---

## **10) Relación con Native Apps y Native Code**

- **Native Apps:** Java/Kotlin define la lógica principal de la app.
    
- **WebView:** Permite integrar contenido web, controlado desde Java.
    
- **JavaScript:** Se ejecuta dentro del WebView, pudiendo interactuar con la app si se usa `addJavascriptInterface()`.
    
- Esta combinación permite **apps híbridas**, pero requiere cuidado por seguridad.