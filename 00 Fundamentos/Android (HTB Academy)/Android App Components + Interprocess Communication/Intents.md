# Intents en Android

## 1️⃣ ¿Qué es un Intent?

Un **Intent** es un objeto de mensajería que Android utiliza para **solicitar una acción** a otro componente del sistema. Es el mecanismo fundamental para la **comunicación entre componentes** dentro de una aplicación y, en algunos casos, entre aplicaciones diferentes.

### Características clave:

*   Es una **abstracción de una operación**: describe qué se quiere hacer, no cómo.
*   Puede especificar:
    *   **Acción** (ej. `ACTION_VIEW`, `ACTION_SEND`)
    *   **Datos** (URI, MIME)
    *   **Componente destino** (en Intents explícitos)
    *   **Extras** (información adicional en pares clave–valor)

### Componentes que interactúan con Intents:

*   **Activities** → Pantallas con interfaz gráfica.
*   **Services** → Procesos en segundo plano.
*   **Broadcast Receivers** → Escuchadores de eventos globales.

Aunque no fueron diseñados como mecanismo IPC formal, en la práctica **pueden usarse para comunicación entre procesos**, por ejemplo, cuando una app invoca un Service que corre en otro proceso.

***

## 2️⃣ ¿Para qué se usan los Intents?

Los Intents son esenciales en Android porque permiten:

1.  **Iniciar una Activity**  
    Ejemplo: abrir una pantalla de detalle desde una lista.
2.  **Iniciar un Service**  
    Ejemplo: descargar un archivo en segundo plano.
3.  **Enviar un Broadcast**  
    Ejemplo: notificar que la batería está baja.

Estos tres casos son los pilares del flujo de interacción en Android.

***

## 3️⃣ Iniciar una Activity con Intents

Las Activities son pantallas que conforman la interfaz de usuario. Para abrir una nueva Activity desde otra, se utiliza un Intent.

### Ejemplo práctico:

```java
Intent intent = new Intent(this, ContactDetailActivity.class);
intent.putExtra("contact_id", selectedContactId);
startActivity(intent);
```

**Explicación técnica:**

*   Se crea un **Intent explícito**, indicando la clase destino (`ContactDetailActivity`).
*   Se añade un **extra** (`contact_id`) para pasar datos.
*   El método `startActivity()` delega en el **ActivityManagerService**, que:
    *   Resuelve el Intent.
    *   Instancia la Activity destino.
    *   Llama a su ciclo de vida (`onCreate()`), pasando el Intent.

Este mecanismo permite **navegación interna** y **transferencia de datos** entre pantallas.

***

## 4️⃣ Iniciar un Service con Intents

Los Services son componentes que ejecutan tareas en segundo plano, sin interfaz gráfica. Se pueden iniciar con un Intent.

### Ejemplo práctico:

```java
Intent intent = new Intent(this, DownloadService.class);
intent.putExtra("file_url", fileUrl);
startService(intent);
```

**Flujo interno:**

*   `startService()` envía el Intent al **ActivityManagerService**.
*   El sistema crea el Service (si no existe) y llama a `onStartCommand()`, pasando el Intent.
*   El Service recupera los datos y ejecuta la tarea (ej. descarga).

Este patrón es común para operaciones largas (descargas, sincronización, etc.).

***

## 5️⃣ Enviar un Broadcast con Intents

Un Broadcast es un mensaje que se envía para **notificar un evento**. Puede ser del sistema (ej. batería baja) o personalizado por la app.

### Ejemplo práctico:

```java
Intent intent = new Intent("com.example.ACTION_BATTERY_LOW");
sendBroadcast(intent);
```

**Flujo interno:**

*   `sendBroadcast()` entrega el Intent al **BroadcastQueue** del sistema.
*   El sistema busca todos los **BroadcastReceivers** registrados para esa acción.
*   Invoca su método `onReceive()` con el Intent.

Esto permite **comunicación global** entre componentes.

***

## 6️⃣ Tipos de Intents

Existen dos tipos principales:

### ✅ Intents Explícitos

*   Se indica el **componente exacto** (clase destino).
*   Uso típico: navegación interna entre Activities o invocación de Services propios.

**Ejemplo:**

```java
Intent intent = new Intent(this, TargetActivity.class);
startActivity(intent);
```

**Características técnicas:**

*   El sistema **no necesita resolver** el Intent → destino directo.
*   Menos ambigüedad → más predecible.

***

### ✅ Intents Implícitos

*   No se indica el componente exacto, sino la **acción** y opcionalmente datos.
*   El sistema busca qué app puede manejar esa acción mediante **intent-filters**.

**Ejemplo:**

```java
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse("https://www.example.com"));
startActivity(intent);
```

**Resolución interna:**

*   El sistema consulta el **PackageManager**.
*   Busca componentes con `intent-filter` que coincidan con:
    *   **Action**
    *   **Data** (URI y MIME)
    *   **Category**
*   Si hay varias coincidencias → muestra un **chooser**.

***

### Elementos clave en la resolución:

*   **Action** → qué se quiere hacer (`VIEW`, `SEND`, etc.).
*   **Data** → URI (ej. `http://`, `content://`).
*   **Type** → MIME (ej. `image/*`).
*   **Category** → contexto (ej. `DEFAULT`).

***

## 7️⃣ Paso de datos con Intents

Los Intents pueden transportar información mediante **pares clave–valor** llamados **extras**.

### Ejemplo:

```java
Intent intent = new Intent(this, TargetActivity.class);
intent.putExtra("key", "value");
startActivity(intent);
```

**Detalles técnicos:**

*   Los extras se almacenan en un objeto `Bundle`.
*   Soportan tipos primitivos, Strings, arrays, objetos `Parcelable` y `Serializable`.
*   Se recuperan en el destino con:

```java
String value = getIntent().getStringExtra("key");
```

**Usos comunes:**

*   Pasar IDs, nombres, flags de configuración entre componentes.
*   Transferir URIs o rutas de ficheros.

***

## 8️⃣ ¿Por qué son importantes los Intents?

*   Son el **pegamento** que une los componentes de Android.
*   Permiten **modularidad** y **reutilización**.
*   Facilitan la **integración entre apps** (ej. compartir contenido).
*   Son clave para entender el **flujo interno** de una aplicación.

Desde el punto de vista arquitectónico:

*   Intents definen **contratos de comunicación**.
*   Reducen acoplamiento entre componentes.
*   Son gestionados por el **ActivityManagerService** y el **PackageManager**.

***

## 9️⃣ Intents y ADB (visión teórica)

Además de código, los Intents pueden enviarse desde la línea de comandos usando **ADB**. Esto es útil para:

*   **Probar flujos internos** sin modificar la app.
*   **Automatizar pruebas funcionales**.

Ejemplo básico:

```bash
adb shell am start -n com.example/.TargetActivity
```

Esto indica:

*   `am start` → iniciar una Activity.
*   `-n` → componente explícito (`paquete/.Clase`).

También se pueden añadir extras:

```bash
adb shell am start -n com.example/.TargetActivity --es key "value"
```

***

## 🧠 Idea clave final

Un Intent es **un mensaje que solicita una acción**.  
Su importancia radica en que:

*   Define cómo se comunican los componentes.
*   Permite modularidad y flexibilidad.
*   Es esencial para comprender el flujo de una app Android.
