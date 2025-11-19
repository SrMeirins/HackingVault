## **1️⃣ Qué es un Service**

Un **Service** en Android es un **componente que se ejecuta en segundo plano**, es decir, no tiene interfaz visual. Permite que la app realice tareas mientras el usuario hace otras cosas en el dispositivo.

**Ejemplos comunes:**

- Reproducir música
    
- Descargar archivos grandes
    
- Sincronizar datos con un servidor remoto
    

💡 **Analogía:** Un asistente invisible que hace tareas por ti mientras usas otras apps.

**Pentesting:** Un servicio mal configurado o expuesto (`exported=true`) puede ser atacado por otras apps instaladas en el dispositivo.

---

## **2️⃣ Tipos de Services**

Android ofrece tres tipos principales de servicios:

---

### **🟢 Foreground Service (Servicio en primer plano)**

- Requiere **notificación visible al usuario**
    
- Funciona aunque la app esté minimizada
    
- Ejemplo: reproductor de música, navegación GPS
    

**Código de ejemplo: Iniciando un Foreground Service desde una Activity**

```java
// Archivo: MainActivity.java (en app/src/main/java/com/example/myapp/)
Intent intent = new Intent(this, MyForegroundService.class);
startService(intent); // Inicia el servicio
```

**Explicación de términos clave:**

- `Intent` → Mensaje que indica qué servicio iniciar
    
- `this` → Referencia al componente actual (Activity que ejecuta el servicio)
    
- `startService(intent)` → Ordena al sistema iniciar el servicio
    

---

### **🟡 Background Service (Servicio en segundo plano)**

- Ejecuta tareas **sin interacción directa con el usuario**
    
- Limitado en Android 8+ si la app no está en primer plano
    
- Ejemplo: sincronización automática de datos
    

**Código de ejemplo: Iniciando un Background Service**

```java
// Archivo: MainActivity.java
Intent intent = new Intent(this, MyBackgroundService.class);
startService(intent);
```

**Conceptos importantes:**

- En Android 8+ el sistema limita los servicios de fondo para **ahorrar batería**
    
- No requiere notificación visible, pero no puede ejecutarse indefinidamente si la app está cerrada
    

---

### **🔵 Bound Service (Servicio vinculado)**

- Permite que **otros componentes o apps** se conecten y usen su funcionalidad
    
- Se comunica mediante **IPC** (Interprocess Communication)
    
- Usamos `bindService()` para establecer conexión
    

```java
// Archivo: MainActivity.java
bindService(new Intent(this, MyBoundService.class), serviceConnection, Context.BIND_AUTO_CREATE);
```

**Explicación:**

- `serviceConnection` → Define cómo se maneja la conexión y callbacks cuando se conecta o desconecta
    
- `BIND_AUTO_CREATE` → Crea el servicio automáticamente si aún no existe
    

**Pentesting:** Un Bound Service mal configurado puede ser accedido por otras apps si se expone sin control.

---

## **3️⃣ Estructura básica de un Service**

Todos los servicios extienden la clase `Service` y pueden implementar diferentes métodos según el tipo (Foreground, Background o Bound).

```java
// Archivo: ExampleService.java (en app/src/main/java/com/example/myapp/)
public class ExampleService extends Service {
    int startMode;       // Qué pasa si el sistema mata el servicio
    IBinder binder;      // Puerta para que otros componentes se conecten
    boolean allowRebind; // Permite reconexión de clientes
}
```

**Explicación:**

- `startMode` → Define comportamiento si el servicio es terminado por el sistema (`START_STICKY`, `START_NOT_STICKY`)
    
- `IBinder binder` → Permite que otros componentes se comuniquen con el servicio
    
- `allowRebind` → Permite reconectar clientes después de desconexión
    

---

## **4️⃣ Ciclo de vida de un Service**

### **🟢 Servicio iniciado con `startService()`**

```java
// Archivo: ExampleService.java
@Override
public int onStartCommand(Intent intent, int flags, int startId) {
    // Aquí ejecutamos la tarea principal del servicio
    return START_STICKY; // Reinicia automáticamente si el sistema lo mata
}
```

- `onStartCommand()` → Se ejecuta cada vez que un componente llama a `startService()`
    
- `START_STICKY` → Permite que el sistema reinicie el servicio automáticamente
    

### **🔵 Servicio iniciado con `bindService()`**

```java
// Archivo: ExampleService.java
@Override
public IBinder onBind(Intent intent) {
    return binder; // Devuelve la “puerta” para que otros componentes se conecten
}
```

- `onBind()` → Se ejecuta cuando un cliente se vincula con `bindService()`
    
- Retorna un objeto `IBinder` para la comunicación
    

---

## **5️⃣ Declarar Services en AndroidManifest.xml**

Todos los servicios deben declararse en el **AndroidManifest.xml** para que Android los reconozca:

```xml
<!-- Archivo: AndroidManifest.xml (en app/src/main/) -->
<application>
    <service android:name=".MyForegroundService"/>
    <service android:name=".MyBackgroundService"/>
    <service android:name=".MyBoundService"/>
</application>
```

- `android:name` → Clase Java que implementa el servicio
    
- `exported="true"` → Permite acceso desde otras apps (¡potencial riesgo de seguridad!)
    

---

## **6️⃣ Ejemplo completo: Foreground Service**

```java
// Archivo: MyForegroundService.java (en app/src/main/java/com/example/myapp/)
public class MyForegroundService extends Service {

    @Override
    public void onCreate() {
        super.onCreate();
        Log.d("Service", "Servicio creado");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // Mostrar notificación al usuario
        Notification notification = new Notification.Builder(this, "channel1")
                .setContentTitle("Servicio Activo")
                .setContentText("El servicio está ejecutándose")
                .setSmallIcon(R.drawable.ic_service)
                .build();

        startForeground(1, notification); // Obligatorio para Foreground Service

        // Simular tarea larga
        new Thread(() -> {
            try { Thread.sleep(10000); } catch (InterruptedException e) {}
            stopSelf(); // Termina el servicio
        }).start();

        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null; // No es Bound Service
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        Log.d("Service", "Servicio detenido");
    }
}
```

**Explicación paso a paso:**

1. `onCreate()` → Se crea el servicio
    
2. `onStartCommand()` → Comienza la tarea principal y muestra notificación
    
3. `startForeground()` → Obligatorio para servicios en primer plano
    
4. `new Thread(...)` → Ejecuta tarea larga sin bloquear la app
    
5. `stopSelf()` → Finaliza el servicio automáticamente
    
6. `onBind()` → Retorna null porque no es Bound Service
    
7. `onDestroy()` → Limpia recursos al terminar el servicio
    

💡 **Ubicación del código:** Todos los servicios se encuentran en **app/src/main/java/com/example/myapp/**, cada uno en su archivo `.java` separado.

---

## **7️⃣ Resumen para principiantes**

- Los Services **no tienen interfaz visual**, trabajan en segundo plano
    
- Tipos principales: **Foreground, Background y Bound**
    
- Todos deben estar **declarados en el manifest**
    
- Se comunican usando **Intents** (para iniciar) y **Binder** (para vinculación)
    
- Desde **pentesting**, los servicios mal configurados (`exported=true`) pueden ser un punto de entrada para ataques