El **código nativo** es aquel que se compila directamente para ejecutarse sobre una arquitectura específica de procesador (ARM, x86, etc.). En Android, esto permite que ciertas partes de una aplicación tengan **mayor rendimiento**, accedan de forma más eficiente al hardware y protejan mejor la lógica crítica de ingeniería inversa.

Android Studio permite integrar código nativo a través del **Native Development Kit (NDK)**, escribiendo partes de la app en **C o C++**, mientras la lógica principal sigue en **Java o Kotlin**.

![[Pasted image 20251118110135.png]]
## **Ventajas del código nativo**

- Rendimiento superior para operaciones intensivas (gráficos, criptografía, procesamiento de datos).
    
- Acceso directo a hardware y librerías de C/C++ existentes.
    
- Difícil de revertir en ingeniería inversa.
    
- Reducción de latencia en funciones críticas.
    

---

# **1) Estructura de un proyecto Native C++**

En Android Studio:  
`New Project -> Native C++`

Opciones principales:

- **C++ Standard:** `Toolchain Default`
    
- Nombre de la app y paquete
    
- Finish
    

**Estructura típica:**

```
app/
├─ manifests/AndroidManifest.xml
├─ java/com/example/myapplication/MainActivity.java
├─ cpp/native-lib.cpp
├─ res/layout/activity_main.xml
├─ res/values/strings.xml
└─ CMakeLists.txt
```

---

# **2) Código C++ nativo (native-lib.cpp)**

```cpp
#include <jni.h>      // Define tipos y funciones JNI (jstring, jobject, etc.)
#include <string>     // Proporciona std::string para manejar texto

// extern "C" evita name mangling y permite que Java encuentre la función
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_myapplication_MainActivity_stringFromJNI(
        JNIEnv* env,      // Puntero al entorno JNI (interacción con Java)
        jobject /* this */) { // Referencia al objeto Java que llamó la función
    // Creamos una cadena de texto en C++
    std::string hello = "Hello from C++";
    
    // Convertimos la cadena C++ a java.lang.String y la devolvemos a Java
    return env->NewStringUTF(hello.c_str());
}
```

### **Explicación línea por línea**

1. `#include <jni.h>` → Incluye las definiciones para interactuar con Java desde C/C++. Contiene tipos como `JNIEnv*`, `jstring` y funciones para crear objetos y llamar métodos en Java.
    
2. `#include <string>` → Permite usar `std::string`, la clase estándar de C++ para cadenas de texto.
    
3. `extern "C"` → Evita que C++ cambie el nombre de la función durante la compilación (name mangling), garantizando que Java pueda localizarla.
    
4. `JNIEXPORT jstring JNICALL` → Macros necesarias para declarar funciones nativas exportadas según convención de llamada JNI.
    
5. `Java_com_example_myapplication_MainActivity_stringFromJNI` → Convención de nombres JNI: `Java_` + paquete + clase + método. Permite a Java localizar esta función.
    
6. `JNIEnv* env` → Puntero que actúa como "puente" para llamar funciones Java desde C++.
    
7. `jobject /* this */` → Referencia al objeto Java que invoca la función.
    
8. `std::string hello = "Hello from C++";` → Creamos una cadena en memoria C++.
    
9. `hello.c_str()` → Devuelve un puntero (`const char*`) al buffer de caracteres de la cadena.
    
10. `env->NewStringUTF(hello.c_str());` → Convierte la cadena de C++ a `java.lang.String` y la devuelve a Java.
    

**Concepto clave: Punteros**

- Un **puntero** es una variable que guarda la dirección de memoria de otra variable.
    
- En `hello.c_str()`, estamos pasando un puntero al buffer interno de la cadena C++ a JNI.
    

---

# **3) Código Java que llama al código nativo**

```java
package com.example.myapplication;

import androidx.appcompat.app.AppCompatActivity;
import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {
    TextView message;

    // Carga la librería nativa al iniciar la app
    static {
        System.loadLibrary("myapplication");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Conecta la UI XML con esta Activity
        setContentView(R.layout.activity_main);

        // Vincula el TextView a la variable 'message'
        message = findViewById(R.id.sample_text);

        // Llama al método nativo y muestra el resultado
        message.setText(stringFromJNI());
    }

    // Declaración del método nativo
    public native String stringFromJNI();
}
```

### **Explicación línea por línea**

1. `static { System.loadLibrary("myapplication"); }`
    
    - Carga `libmyapplication.so` en memoria al inicio de la app.
        
2. `public native String stringFromJNI();`
    
    - Declara el método nativo. La implementación real está en C++.
        
3. `setContentView(R.layout.activity_main);`
    
    - Conecta la interfaz XML `activity_main.xml` con la clase Java.
        
4. `findViewById(R.id.sample_text);`
    
    - Busca un objeto de la UI (TextView) por su ID.
        
5. `message.setText(stringFromJNI());`
    
    - Llama al método nativo y coloca el texto resultante en la UI.
        

---

# **4) CMakeLists.txt**

```cmake
add_library(
        myapplication  # Nombre de la librería
        SHARED         # Librería compartida (.so)
        native-lib.cpp # Archivo fuente C++
)
```

- Define el nombre de la librería y el archivo fuente.
    
- `SHARED` indica que se genera un archivo `.so` dinámico.
    

---

# **5) Cargar librerías dinámicamente en tiempo de ejecución**

```java
public class Update {
    public native String stringFromJNI();

    public String update(String path_sd_card, String filesDir){
        try (FileInputStream inputStream = new FileInputStream(new File(path_sd_card + "/Download/libupgrade.so"));
             FileOutputStream outputStream = new FileOutputStream(new File(filesDir + "/libupgrade.so"))) {

            FileChannel inChannel = inputStream.getChannel();
            FileChannel outChannel = outputStream.getChannel();
            inChannel.transferTo(0, inChannel.size(), outChannel);

        } catch (IOException e) {
            e.printStackTrace();
        }

        // Carga la librería en tiempo de ejecución
        System.load(filesDir + "/libupgrade.so");

        // Llama al método nativo cargado
        return stringFromJNI();
    }
}
```

### Explicación:

- Copia la librería `.so` desde almacenamiento externo al directorio interno de la app.
    
- `System.load(path)` carga la librería dinámicamente.
    
- Riesgo: si un atacante reemplaza `.so`, puede ejecutar código arbitrario.
    

---

# **6) Conceptos avanzados de JNI y C++**

|Concepto|Explicación|
|---|---|
|Puntero|Variable que guarda dirección de memoria de otra variable.|
|Local Reference|Válida solo dentro de la función nativa; liberada automáticamente.|
|Global Reference|Persiste más allá de la función; se libera con `DeleteGlobalRef`.|
|Weak Global Reference|Similar a global, pero no evita garbage collection.|
|Convertir jstring|`const char* str = env->GetStringUTFChars(jStr, nullptr);` → `std::string cppStr(str);`|
|Excepciones JNI|`env->ExceptionCheck()`, `ExceptionDescribe()`, `ExceptionClear()`|

---

# **7) Flujo completo de ejecución**

```
Java Activity
    │
    │ Llama a método nativo
    ▼
JNIEnv* env (JNI Bridge)
    │
    │ Invoca funciones C++ en native-lib.cpp
    ▼
C++ realiza operaciones y devuelve datos
    │
    │ NewStringUTF convierte std::string → java.lang.String
    ▼
Java TextView muestra el resultado
```

---

# **8) Conceptos finales**

- Código nativo mejora rendimiento y seguridad, pero **requiere cuidado**: mala gestión de memoria o librerías dinámicas inseguras pueden causar **crashes o ejecución remota de código**.
    
- Conocer JNI y punteros es clave para **ingeniería inversa** y pentesting en apps Android.
    
