# ✅ **1. Qué es exactamente un Broadcast Receiver**

Un **Broadcast Receiver** es un componente de Android que permite que tu app **escuche eventos** (mensajes) emitidos por:

* El **sistema operativo**
* Otras **aplicaciones**
* La propia aplicación

Cuando ocurre un evento, si tu app tiene un Broadcast Receiver registrado para ese tipo de evento, Android ejecuta el método:

```java
onReceive()
```

💡 **Analogía sencilla:**
Imagina que tu móvil es una gran ciudad.
Los broadcasts son “anuncios por megafonía” (eventos).
Un Broadcast Receiver es un “guardia” que escucha algunos anuncios específicos y actúa cuando oye uno que reconoce.

---

# 🎯 **¿Para qué sirven los Broadcast Receivers?**

Algunos ejemplos del mundo real:

* Saber si el dispositivo **empieza o deja de cargarse**
* Saber si el usuario **se conectó a una red Wi‑Fi**
* Saber cuando se termina la **descarga de un archivo**
* Ejecutar código cuando el dispositivo **termina de arrancar** (`BOOT_COMPLETED`)
* Comunicación entre apps mediante Intents
* Comunicación interna entre componentes de la app

---

# 🔐 **Broadcast Receivers desde la perspectiva de Pentesting**

Broadcast Receivers son un vector clásico de ataque porque:

### ❗ 1. Pueden estar **expuestos** a otras aplicaciones

```xml
android:exported="true"
```

Esto permite que **cualquier app** del sistema pueda enviarles un Intent para activar su código.

### ❗ 2. Si aceptan datos sin validación → se puede inyectar contenido malicioso

### ❗ 3. Pueden ejecutarse con **permisos más altos** que la app atacante

Por ejemplo, un Broadcast Receiver vulnerable podría permitir que otra app ejecute acciones privilegiadas como:

* borrar datos
* enviar SMS
* acceder a archivos internos
* iniciar actividades sensibles

### ❗ 4. Si no requieren permisos → cualquiera puede activarlos

Ejemplo clásico de CVE en Android apps.

---

# 🧩 **2. Cómo funciona un Broadcast Receiver técnicamente**

Un Broadcast Receiver se compone de:

### 1️⃣ Una **clase Java** que extiende `BroadcastReceiver`

Aquí defines qué hace cuando recibe un Intent.

### 2️⃣ Un **IntentFilter**

Indica qué mensajes debe escuchar ese receptor.

### 3️⃣ Una **declaración en AndroidManifest.xml**

(para Broadcast Receivers “estáticos”).

---

# 🧱 **3. Ejemplo base de un Broadcast Receiver**

### 📄 Archivo: `MyBroadcastReceiver.java`

📂 Ruta: `app/src/main/java/com/example/myapp/`

```java
public class MyBroadcastReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {

        // 1. Obtenemos la acción del intent recibido (qué evento ocurrió)
        String action = intent.getAction();

        // 2. Si la acción no está vacía
        if (action != null) {

            // 3. Según la acción, ejecutamos código distinto
            switch (action) {

                case Intent.ACTION_POWER_CONNECTED:
                    Log.d("BroadcastReceiver", "El dispositivo está conectado a la corriente.");
                    break;

                case Intent.ACTION_POWER_DISCONNECTED:
                    Log.d("BroadcastReceiver", "El dispositivo se ha desconectado de la corriente.");
                    break;

                default:
                    Log.d("BroadcastReceiver", "Acción recibida: " + action);
                    break;
            }
        }
    }
}
```

---

# 🔍 **Explicación

### `public class MyBroadcastReceiver extends BroadcastReceiver`

Esto crea una clase que hereda de `BroadcastReceiver`, lo que indica a Android que esta clase va a **recibir broadcasts**.

### `onReceive(Context context, Intent intent)`

Este método se ejecuta automáticamente cuando ocurre un evento para el que este Broadcast Receiver está registrado.

Conceptos clave:

* **Context** → información sobre el estado global de la aplicación (permite iniciar activities, servicios, etc.)
* **Intent** → mensaje que describe qué ocurrió (la acción y datos adicionales)

### `intent.getAction()`

Devuelve un string con la acción del evento, por ejemplo:

* `"android.intent.action.ACTION_POWER_CONNECTED"`
* `"android.intent.action.ACTION_POWER_DISCONNECTED"`

### `switch (action)`

Permite reaccionar **según qué evento** esté ocurriendo.

---

# 🗂️ **4. Declarar el Broadcast Receiver en el Manifest**

📄 Archivo: `AndroidManifest.xml`
📂 Ruta: `app/src/main/`

```xml
<application>
    <receiver android:name=".MyBroadcastReceiver" android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.ACTION_POWER_CONNECTED" />
            <action android:name="android.intent.action.ACTION_POWER_DISCONNECTED" />
        </intent-filter>
    </receiver>
</application>
```

---

# 🔍 **Explicación

### `<receiver android:name=".MyBroadcastReceiver">`

Le dice a Android:

➡️ “Existe una clase llamada `MyBroadcastReceiver` que quiere recibir broadcasts”.

### `android:exported="true"`

Significa:

➡️ “Otras apps pueden enviarle Intent a este Broadcast Receiver”.

**⚠️ IMPORTANTE PARA PENTESTING:**
Si está en `true`, **es un potencial vector de ataque**.

### `<intent-filter>`

Define qué eventos escucha.

---

# 🧨 **5. Cómo enviar un Broadcast desde tu app**

📄 Archivo: `MainActivity.java`
📂 `app/src/main/java/com/example/myapp/`

```java
Intent intent = new Intent("com.example.myapp.CUSTOM_BROADCAST");
sendBroadcast(intent);
```

### Explicado:

* Creamos un Intent con acción personalizada.
* Llamamos a `sendBroadcast()` → lo envía a todos los receptores compatibles.

---

# 🧰 **Tipos de Broadcasts**

| Método                                  | Para qué sirve                                                  |
| --------------------------------------- | --------------------------------------------------------------- |
| `sendBroadcast()`                       | Envía el Intent a todos los receptores disponibles              |
| `sendOrderedBroadcast()`                | Envía el Intent uno por uno según prioridad                     |
| `LocalBroadcastManager.sendBroadcast()` | Envía mensajes dentro de la misma app (deprecated desde API 28) |

---

# 🔥 **6. Broadcast Receivers Dinámicos**

También puedes registrar un Broadcast Receiver **desde código**, no solo en el manifest.

📄 Archivo: `MainActivity.java`

```java
MyBroadcastReceiver receiver = new MyBroadcastReceiver();

IntentFilter filter = new IntentFilter();
filter.addAction(Intent.ACTION_POWER_CONNECTED);
filter.addAction(Intent.ACTION_POWER_DISCONNECTED);

registerReceiver(receiver, filter); // Activa el receptor
```

### Desregistrar:

```java
@Override
protected void onDestroy() {
    super.onDestroy();
    unregisterReceiver(receiver);
}
```

---

# 🔐 **7. Broadcast Receivers y Pentesting — Lo que debes saber**

### 🔴 1. Riesgo de Intent Spoofing

Si un receiver está `exported=true` y **no exige permisos**, una app maliciosa puede:

* Activar funciones internas
* Hacer que la app ejecute código inesperado
* Enviar datos maliciosos al método `onReceive()`

### 🔴 2. Riesgo de DoS (Denial of Service)

Una app atacante puede enviar miles de broadcasts, saturando la aplicación.

### 🔴 3. Riesgo por receivers de BOOT_COMPLETED

Los que se ejecutan al encender el dispositivo pueden usarse para persistencia maliciosa.

### 🔴 4. Riesgo por falta de permisos

Si no se usa:

```xml
android:permission="..."
```

cualquiera puede activarlo.

---

# 🛡️ **Buenas prácticas (tanto desarrollo como seguridad)**

| Recomendación                                      | Razón                                    |
| -------------------------------------------------- | ---------------------------------------- |
| Usar `exported="false"` cuando sea posible         | Evita ataques entre apps                 |
| Usar permisos en el manifest                       | Solo apps autorizadas podrán interactuar |
| Validar siempre el contenido del Intent            | Evita inyecciones o spoofing             |
| Preferir receptores dinámicos en lugar de manifest | Son más seguros                          |
| Evitar acciones genéricas como `"*"`               | Crea superficies enormes de ataque       |

---

# 🧩 **Ejemplo Completo: Receiver Personalizado**

### 📄 Receiver

```java
// Archivo: CustomReceiver.java
public class CustomReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String data = intent.getStringExtra("data");
        Log.d("CustomReceiver", "Dato recibido: " + data);
    }
}
```

### 📄 Manifest

```xml
<receiver android:name=".CustomReceiver" android:exported="false">
    <intent-filter>
        <action android:name="com.example.myapp.CUSTOM" />
    </intent-filter>
</receiver>
```

### 📄 Envío desde MainActivity

```java
Intent intent = new Intent("com.example.myapp.CUSTOM");
intent.putExtra("data", "Hola mundo");
sendBroadcast(intent);
```

---

# 🟦 **Resumen Final

1. Un Broadcast Receiver escucha eventos → **onReceive()**
2. Se usa para reaccionar a sucesos del sistema o de otras apps
3. Debes declararlo en el manifest o registrarlo en tiempo de ejecución
4. Se comunica mediante **Intents**
5. Desde pentesting, es un vector clave por:

   * Intent Spoofing
   * Falta de permisos
   * Exported components
6. Entender Broadcast Receivers es crucial para:

   * Crear apps Android reales
   * Hacer auditoría de seguridad móvil
