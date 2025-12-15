# Deep Links en Android

## 1️⃣ ¿Qué es un Deep Link?

Un **Deep Link** es un mecanismo que permite a los usuarios **acceder directamente a contenido específico dentro de una aplicación** mediante un enlace (URL) que puede encontrarse en:

*   Sitios web
*   Correos electrónicos
*   Mensajes
*   Notificaciones

En lugar de abrir la pantalla principal de la app, el Deep Link lleva al usuario **exactamente al recurso indicado** (por ejemplo, un producto, una noticia o una sección concreta).

### ¿Por qué son importantes?

*   Mejoran la **experiencia del usuario**.
*   Permiten **integración fluida** entre web y app.
*   Son esenciales para **marketing**, **notificaciones push** y **flujos complejos**.

**Ejemplo práctico:**

*   Un usuario recibe un correo sobre una oferta en un producto.
*   Al pulsar el enlace, se abre la app directamente en la pantalla del producto.
*   Si la app no está instalada, se redirige a Google Play para descargarla.

***

## 2️⃣ Tipos de Deep Links en Android

Existen dos tipos principales:

### ✅ **Standard Deep Links**

*   Usan esquemas personalizados (ej. `app://myapp/products/cpu`).
*   Permiten abrir la app si está instalada.
*   **Limitación**: Android **no verifica la propiedad del esquema**, lo que puede generar riesgos (cualquier app puede declararse como handler).

***

### ✅ **Android App Links**

*   Usan URLs HTTP/HTTPS verificadas (ej. `https://www.myapp.com/products/cpu`).
*   Introducidos en Android 6.0 para mejorar seguridad.
*   El sistema **verifica la propiedad del dominio** mediante un archivo `assetlinks.json` en el servidor.
*   Si la app no está instalada, el enlace se abre en el navegador.

***

## 3️⃣ ¿Cómo funciona un Deep Link?

Cuando el usuario pulsa un enlace:

1.  Android analiza la URL.
2.  Busca en el **AndroidManifest.xml** si alguna Activity tiene un **intent-filter** que coincida con:
    *   **Action** (`VIEW`)
    *   **Categories** (`DEFAULT`, `BROWSABLE`)
    *   **Data** (scheme, host, path)
3.  Si encuentra coincidencia:
    *   Lanza la Activity correspondiente.
    *   Pasa la URL al Intent (`getIntent().getData()`).

***

## 4️⃣ Ejemplo práctico: Standard Deep Link

### 4.1 Código HTML en la web:

**HTML:**

    <div>
        <p>Compra nuestras últimas piezas de PC.</p>
        app://myapp/products/cpuVer producto</a>
    </div>

**Explicación:**

*   `app://` → esquema personalizado.
*   `myapp` → host.
*   `/products/cpu` → ruta que identifica el recurso.

***

### 4.2 Configuración en el Manifest:

```xml
<activity android:name=".ProductsActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="app"
              android:host="myapp"
              android:pathPrefix="/products/" />
    </intent-filter>
</activity>
```

**Elementos clave:**

*   `android:scheme="app"` → protocolo del enlace.
*   `android:host="myapp"` → dominio lógico.
*   `android:pathPrefix="/products/"` → prefijo de la ruta.

***

### 4.3 Manejo en la Activity:

```java
public class ProductsActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_products);

        Intent intent = getIntent();
        String action = intent.getAction();
        Uri data = intent.getData();

        if (Intent.ACTION_VIEW.equals(action) && data != null) {
            String productName = data.getLastPathSegment();
            if ("cpu".equals(productName)) {
                // Consultar base de datos y mostrar detalles del producto
            }
        }
    }
}
```

**Explicación:**

*   `getIntent().getData()` devuelve la URL completa.
*   `getLastPathSegment()` obtiene la última parte (`cpu`).
*   Se usa para cargar el contenido correspondiente.

***

## 5️⃣ Ejemplo práctico: Android App Link

### dominio real.

*   `android:autoVerify="true"` → activa la verificación del dominio.

***

### 5.3 Verificación del dominio:

*   Se coloca un archivo `assetlinks.json` en `https://www.myapp.com/.well-known/assetlinks.json`.
*   Este archivo indica que la app es propietaria del dominio.
*   Android verifica esto para evitar que otras apps intercepten el enlace.

***

## 6️⃣ Riesgos y buenas prácticas

### Riesgos:

*   **Standard Deep Links**:
    *   No hay verificación de propiedad → otra app puede interceptar el esquema.
        -Parámetros inseguros\*\*:
    *   Ejemplo: `https://www.myapp.com/home?uid=50&token=XYZ`.
    *   Si la app no valida `uid` y `token`, puede haber acceso no autorizado.

### Buenas prácticas:

*   Preferir **Android App Links** (verificación de dominio).
*   Validar todos los parámetros recibidos.
*   No incluir datos sensibles en la URL (tokens, credenciales).
*   Usar HTTPS siempre.
*   Implementar controles de autenticación y autorización en la Activity.

***

## 7️⃣ ¿Por qué son importantes los Deep Links?

*   Mejoran la **experiencia del usuario**.
*   Permiten **integración fluida** entre web y app.
*   Son esenciales para:
    *   **Marketing** (campañas, promociones).
    *   **Notificaciones push**.
    *   **Flujos complejos** (ej. abrir una pantalla específica desde un correo).

***

## 🧠 Idea clave final

Un Deep Link es **un puente entre el mundo web y la app móvil**.  
Bien implementado:

*   Mejora la experiencia.
*   Aumenta la conversión.
*   Mantiene la seguridad.

Mal implementado:

*   Puede abrir la puerta a **vulnerabilidades graves**.