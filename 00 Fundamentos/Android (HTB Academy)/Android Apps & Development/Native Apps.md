## 🧩 ¿Qué es una _Native App_?

Una **aplicación nativa** es un programa creado **específicamente para un sistema operativo concreto**, utilizando su propio lenguaje y herramientas oficiales.

En Android, esto significa:

- Lenguajes principales: **Java** y **Kotlin**
    
- Entorno de desarrollo oficial: **Android Studio**
    
- Herramientas base: **Android SDK**
    

Google promueve **Kotlin** como lenguaje por defecto en la actualidad, pero **Java sigue siendo muy utilizado**, especialmente en proyectos antiguos, cursos, pentesting y análisis de apps reales.

---

# 🏗️ **Estructura básica de un proyecto Android**

Cuando creas un proyecto en Android Studio, aparecen carpetas muy importantes:

```
app/
 ├─ manifests/          → AndroidManifest.xml
 ├─ java/               → Código Java/Kotlin
 │    └─ MainActivity.java
 └─ res/                → Recursos (layouts, imágenes, strings…)
       ├─ layout/       → activity_main.xml (interfaces)
       ├─ values/       → strings.xml, colors.xml, themes.xml
```

---

# 🎨 **Layouts (Interfaces de usuario)**

Los _layouts_ definen **cómo se ve la app**: texto, botones, imágenes, etc.  
En Android se construyen utilizando **XML**.

Vamos a estudiar el archivo **activity_main.xml**, donde se crea una interfaz simple con:

- Un título
    
- Un botón
    
- Un texto que cambia al pulsar el botón
    

### 📄 Código del layout

```xml
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout
    xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    tools:context=".MainActivity">

    <TextView
        android:id="@+id/title"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="My Application"
        android:textSize="32sp"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintVertical_bias="0.097" />

    <Button
        android:id="@+id/button"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Button"
        app:layout_constraintTop_toBottomOf="@+id/title"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintVertical_bias="0.403" />

    <TextView
        android:id="@+id/message"
        android:layout_width="380dp"
        android:layout_height="31dp"
        android:text="@string/message"
        android:textSize="20sp"
        android:textAlignment="center"
        android:textIsSelectable="true"
        app:layout_constraintTop_toBottomOf="@+id/button"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintVertical_bias="0.25" />

</androidx.constraintlayout.widget.ConstraintLayout>
```

---

# 🔍 **Explicación de atributos importantes**

|Atributo|Explicación|
|---|---|
|`tools:context=".MainActivity"`|Solo sirve para que Android Studio sepa qué actividad usa este layout en la vista de diseño. No afecta a la app real.|
|`android:id="@+id/...`|Identificador único que permite acceder desde Java/Kotlin. Con `@+id` se crea si no existía.|
|`android:text="..."`|Texto mostrado. Puede ser literal o tomado de `strings.xml`, lo recomendado para organizar y traducir.|

### Ejemplo del archivo `strings.xml`:

```xml
<resources>
    <string name="app_name">My Application</string>
    <string name="message">Hello World!</string>
</resources>
```

Estos textos se referencian mediante la clase auto-generada `R`.

---

# 🧠 **La clase R: el índice de todos los recursos**

Cada elemento en `/res` crea una entrada en:

```
R.java
```

Ejemplo:

- `R.id.message` → apunta al TextView con `android:id="@+id/message"`
    
- `R.string.message` → apunta al string `"Hello World!"`
    

En pentesting y reversing, es clave entender esta relación.

---

# 🧩 **MainActivity.java — El cerebro de la app**

Este archivo contiene la lógica que controla la interfaz.

### 📄 Código:

```java
package com.example.myapplication;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {
    TextView message;
    Button button;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        message = (TextView)findViewById(R.id.message);
        button = (Button)findViewById(R.id.button);

        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                message.setText("Hello from Java!");
            }
        });
    }
}
```

---

# 📚 **Explicación clara

## 1️⃣ `public class MainActivity extends AppCompatActivity`

- Define una **Activity**, que es como una pantalla de la app.
    
- `extends AppCompatActivity` significa que hereda comportamientos básicos de Android.
    

## 2️⃣ `onCreate()`

Es el método que Android ejecuta cuando la Activity _nace_.  
Todo lo que pongas aquí ocurre justo al abrir la app.

## 3️⃣ `setContentView(R.layout.activity_main)`

Indica qué archivo XML será la interfaz.

## 4️⃣ Obtener referencias a objetos del layout

```java
message = (TextView)findViewById(R.id.message);
button = (Button)findViewById(R.id.button);
```

Esto permite controlar esos elementos desde código.

## 5️⃣ Acción al pulsar el botón

```java
button.setOnClickListener(new View.OnClickListener() {
    @Override
    public void onClick(View v) {
        message.setText("Hello from Java!");
    }
});
```

Significa:

> Cuando el usuario pulse el botón, cambia el texto del TextView.

---

# 🐦 **Versión en Kotlin (más moderna)**

```kotlin
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val message = findViewById<TextView>(R.id.message)
        val button = findViewById<Button>(R.id.button)

        button.setOnClickListener {
            message.text = "Hello from Java!"
        }
    }
}
```

Diferencias:

- Mucho más corto
    
- No requiere clases anónimas para listeners
    
- Menos código repetitivo
    

---

# 📦 **Crear un APK firmado**

Para instalar una app en un dispositivo real, debe estar **firmada**.

Ruta en Android Studio:

```
Build → Generate Signed Bundle / APK
```

Pasos:

1. Seleccionar **APK**
    
2. Crear un **nuevo keystore**
    
3. Especificar:
    
    - Ruta del keystore
        
    - Contraseña del keystore
        
    - Alias
        
    - Datos del certificado
        
4. Elegir **release**
    
5. Finalizar
    

El APK resultante se genera en:

```
~/AndroidStudioProjects/MyApplication/app/release/app-release.apk
```

Y lo puedes instalar en el móvil o en un emulador.