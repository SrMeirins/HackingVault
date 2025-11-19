## **1️⃣ Qué son los Application Components**

Los **Application Components** son los **bloques fundamentales** de cualquier aplicación Android. Cada componente cumple un rol específico dentro de la app, como:

- **Mostrar interfaz al usuario**
    
- **Ejecutar tareas en segundo plano**
    
- **Recibir mensajes del sistema o de otras apps**
    
- **Gestionar y compartir datos entre aplicaciones**
    

### Principales tipos de componentes

|Componente|Función principal|Ejemplo práctico|
|---|---|---|
|**Activity**|Pantalla de interacción con el usuario|Formulario de login|
|**Service**|Ejecuta procesos en segundo plano|Reproducción de música, sincronización de datos|
|**Broadcast Receiver**|Recibe mensajes del sistema o de otras apps|Detectar conexión WiFi o batería baja|
|**Content Provider**|Comparte datos entre apps|Acceso a contactos, calendario o base de datos|

> Cada componente debe ser declarado en el **AndroidManifest.xml**, que es el archivo de configuración principal de la app.

---

## **2️⃣ Inter-Process Communication (IPC)**

En Android, cada app corre en un **proceso aislado**, por lo que **no pueden acceder directamente a la memoria de otras apps**.  
Para comunicarse, se utiliza **IPC** (Inter-Process Communication).

Ejemplos de IPC:

- Una **Activity** envía datos a otra Activity mediante **Intents**
    
- Un **Service** recibe solicitudes mediante **Intents** o **binders**
    
- Un **Broadcast Receiver** escucha mensajes del sistema o de apps
    
- Un **Content Provider** permite consultar o modificar datos desde otra app
    

> IPC es crítico para la seguridad. Si se implementa mal, puede exponer datos sensibles o permitir que otra app interfiera en el funcionamiento de tu aplicación.

---

## **3️⃣ Activities: definición y características**

Una **Activity** representa **una pantalla dentro de la app**, donde el usuario puede interactuar.

### Características principales:

- Puede ser **pantalla completa, flotante, embebida o multi-ventana**
    
- Puede iniciarse desde otras Activities, apps externas o eventos del sistema
    
- Gestiona **la interfaz y la interacción del usuario**
    
- Controla el **ciclo de vida**, que permite administrar recursos y mantener el rendimiento
    

> Las Activities son la parte **visible y activa de la aplicación**, y entender su flujo es fundamental para aprender a programar y para pruebas de seguridad.

---

## **4️⃣ Ciclo de vida de una Activity**

Cada Activity pasa por **seis callbacks principales**, que son métodos que Android llama automáticamente según el estado de la Activity:

```java
public class ActivityExample extends ApplicationContext {
    protected void onCreate(Bundle savedInstanceState);
    protected void onStart();
    protected void onRestart();
    protected void onResume();
    protected void onPause();
    protected void onStop();
    protected void onDestroy();
}
```

### Flujo visual del ciclo de vida

![[Pasted image 20251118124411.png]]

- **onCreate()** → La Activity se crea
    
- **onStart()** → La Activity se vuelve visible
    
- **onResume()** → La Activity interactúa con el usuario
    
- **onPause()** → La Activity pierde foco (parcial)
    
- **onStop()** → La Activity ya no es visible
    
- **onDestroy()** → La Activity se destruye
    
- **onRestart()** → Se reinicia después de estar detenida
    

---

## **5️⃣ Detalle de cada callback

### **🟦 onCreate()**

- Primer callback cuando se crea la Activity
    
- Se inicializa la **interfaz** y **variables internas**
    
- **Se configuran listeners** (por ejemplo, botones que reaccionan al clic)
    
- Se puede acceder a datos guardados de sesiones previas usando `Bundle savedInstanceState`
    

```java
@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main); // Carga el layout XML
    Toast.makeText(this, "App iniciada", Toast.LENGTH_SHORT).show(); // Mensaje breve en pantalla
}
```

**Explicación de cada línea:**

1. `super.onCreate(savedInstanceState)` → Llama a la implementación base para inicializar correctamente la Activity.
    
2. `setContentView(R.layout.activity_main)` → Carga la interfaz definida en `activity_main.xml`.
    
3. `Toast.makeText(...).show()` → Muestra un mensaje breve flotante al usuario.
    

> Este es un punto crítico para principiantes, ya que aquí **se inicializa todo lo que la Activity necesita**, incluidos datos importantes o conexiones.

---

### **🟦 onStart()**

- La Activity **ya es visible** al usuario
    
- Se pueden iniciar recursos que no requieren interacción directa
    

```java
@Override
protected void onStart() {
    super.onStart();
    Log.d("Lifecycle", "Activity visible");
}
```

---

### **🟦 onResume()**

- La Activity **puede interactuar con el usuario**
    
- Aquí se inician animaciones, reproducción de medios o sensores
    

```java
@Override
protected void onResume() {
    super.onResume();
    startCamera(); // Inicia la cámara si la app lo requiere
}
```

---

### **🟦 onPause()**

- La Activity **pierde foco o queda parcialmente visible**
    
- Se deben liberar recursos no necesarios para ahorrar memoria
    

```java
@Override
protected void onPause() {
    super.onPause();
    stopCamera(); // Detiene la cámara para liberar recursos
}
```

---

### **🟦 onStop()**

- La Activity **ya no es visible**
    
- Guardar datos temporales y liberar recursos pesados
    

```java
@Override
protected void onStop() {
    super.onStop();
    saveDataToCache();
}
```

---

### **🟦 onDestroy()**

- La Activity **se destruye completamente**
    
- Se liberan todos los recursos y conexiones
    

```java
@Override
protected void onDestroy() {
    super.onDestroy();
    closeDatabase(); // Cierra bases de datos y libera memoria
}
```

---

### **🟦 onRestart()**

- La Activity **vuelve a iniciarse** después de haber sido detenida
    

```java
@Override
protected void onRestart() {
    super.onRestart();
    Log.d("Lifecycle", "Activity reiniciada");
}
```

---

## **6️⃣ Qué es un Intent**

Un **Intent** es un **objeto que permite comunicar componentes** dentro de la misma aplicación o con otras aplicaciones.

- **Se usa para iniciar Activities, Services o Broadcasts**
    
- Puede llevar **datos extras** (llave/valor) para que el componente receptor los use
    

**Ejemplo básico de Intent:**

```java
// En el activity Source (e.g., MainActivity.java)
Intent intent = new Intent(this, TargetActivity.class);
intent.putExtra("username", "jorge");
startActivity(intent);
```

**Explicación:**

1. `new Intent(this, TargetActivity.class)` → Crea un intent para iniciar la Activity `TargetActivity`.
    
2. `putExtra("username", "jorge")` → Envía información extra con clave `"username"` y valor `"jorge"`.
    
3. `startActivity(intent)` → Inicia la Activity sin esperar ningún resultado.
    

> Los Intents son la forma principal de **comunicar y pasar datos entre pantallas en Android**.

---

## **7️⃣ startActivity vs startActivityForResult**

- `startActivity()` → Inicia otra Activity **sin esperar resultado**
    
- `startActivityForResult()` → Inicia otra Activity **y espera que devuelva un resultado**
    

```java
int requestCode = 1; // Código único para identificar la respuesta
startActivityForResult(intent, requestCode);
```

---

### **Cómo devolver un resultado desde la Activity lanzada**

```java
Intent resultIntent = new Intent();
resultIntent.putExtra("result_key", "resultado");
setResult(RESULT_OK, resultIntent);
finish(); // Cierra la Activity y devuelve el resultado
```

En la Activity que lanzó:

```java
@Override
protected void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    if (requestCode == 1 && resultCode == RESULT_OK && data != null) {
        String result = data.getStringExtra("result_key");
    }
}
```


---

## **8️⃣ Declarar Activities en el Manifest**

Todo componente debe ser **declarado en AndroidManifest.xml**:

```xml
<activity android:name=".MainActivity">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>

<activity android:name=".SecondActivity" android:exported="true"/>
```

**Explicación:**

- `MAIN` → Activity de inicio (entry point)
    
- `LAUNCHER` → Visible en el launcher del sistema
    
- `exported="true"` → Permite que otras apps accedan a esta Activity (atención, es crítico para seguridad)
    

> Identificar qué Activity es el entry point y si está exportada es importante incluso para pruebas de seguridad.

---

## **✅ Resumen visual del flujo**

![[Pasted image 20251118125803.png]]

- Cada Activity tiene **su propio ciclo de vida**
    
- Los datos entre Activities viajan mediante **Intents**
    
- Las Activities exportadas pueden ser **puntos de acceso a la app**, incluso desde otras aplicaciones o ADB
