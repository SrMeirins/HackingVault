# 📦 Content Providers en Android

## 🧠 Concepto fundamental

Un **Content Provider** es uno de los **cuatro componentes principales de Android**, junto con:

* Activities
* Services
* Broadcast Receivers

Su función principal es **gestionar datos y permitir su acceso de forma controlada**, tanto dentro de la propia aplicación como desde **otras aplicaciones distintas**.

Desde una perspectiva de seguridad, un Content Provider es un **punto crítico de exposición de datos**. Si está mal diseñado o mal configurado, puede permitir a un atacante:

* Leer información sensible
* Modificar datos internos
* Borrar registros
* Abusar de la lógica de negocio

En pentesting Android, los Content Providers se consideran una **superficie de ataque directa**.

---

## 🧩 Doble naturaleza: componente y canal de comunicación

Un Content Provider cumple **dos roles simultáneos** dentro del sistema Android.

### 1️⃣ Como componente de aplicación

Actúa como una capa encargada de:

* Acceder a los datos reales
* Organizar la información
* Definir qué se puede hacer con esos datos

La aplicación **no accede directamente** a la base de datos o al almacenamiento, sino que lo hace **a través del Content Provider**.

Esto introduce una capa de abstracción que, bien implementada, mejora la seguridad. Mal implementada, la rompe.

---

### 2️⃣ Como mecanismo de IPC (Interprocess Communication)

Android aísla cada aplicación en su propio proceso. Para compartir datos entre procesos se usan mecanismos IPC.

El Content Provider es uno de esos mecanismos:

* Permite que una app A acceda a datos de una app B
* Android actúa como intermediario
* El acceso se hace mediante URIs bien definidas

📌 En pentesting esto es clave: **si otra app puede acceder a un Content Provider sin permisos, tú también puedes hacerlo**.

---

## 🗄️ Origen y tipo de datos

Un Content Provider puede gestionar datos que provienen de múltiples fuentes:

* Bases de datos **SQLite**
* Archivos en almacenamiento interno
* Archivos en almacenamiento externo
* Datos cacheados
* Datos obtenidos de APIs remotas

Desde el punto de vista ofensivo:

> No importa dónde estén los datos, importa si puedes llegar a ellos.

---

## 🔄 API estándar basada en CRUD

Todos los Content Providers siguen una **interfaz estándar** basada en operaciones CRUD:

| Operación | Método     | Descripción          |
| --------- | ---------- | -------------------- |
| Create    | `insert()` | Inserta nuevos datos |
| Read      | `query()`  | Consulta datos       |
| Update    | `update()` | Modifica datos       |
| Delete    | `delete()` | Elimina datos        |

Esto tiene una ventaja para el atacante:

* El comportamiento es **predecible**
* Los vectores de ataque son **repetibles**

---

## 🔗 ContentResolver: el intermediario obligatorio

Las aplicaciones **no llaman directamente** al Content Provider.

Siempre pasan por el **ContentResolver**, que:

* Recibe la petición
* Resuelve la URI
* Redirige la llamada al Content Provider correcto

Desde el punto de vista de pentesting:

* El ContentResolver **no valida seguridad**
* La seguridad depende exclusivamente del Provider

---

## 🧵 Acceso asíncrono con CursorLoader

En aplicaciones reales, las consultas suelen ejecutarse en segundo plano usando **CursorLoader**.

Motivo:

* Las operaciones con datos pueden ser lentas
* Bloquear el hilo principal congela la app

Flujo completo:

```
UI / Activity
   ↓
CursorLoader
   ↓
ContentResolver
   ↓
ContentProvider
   ↓
Base de datos / almacenamiento
```

Este flujo no añade seguridad extra, solo mejora la experiencia de usuario.

---

## 🧪 Ejemplo real: User Dictionary Provider

Android incluye un Content Provider por defecto llamado **User Dictionary Provider**, que gestiona el diccionario personal del usuario (palabras añadidas manualmente por el usuario para el teclado).

Este Provider es un buen ejemplo porque:

* Es real
* Viene en el sistema
* Usa exactamente los mismos mecanismos que un Provider de una app cualquiera

Ejemplo de consulta:

```java
cursor = getContentResolver().query(
    UserDictionary.Words.CONTENT_URI,
    projection,
    selectionClause,
    selectionArgs,
    sortOrder
);
```

### 🔍 Explicación línea por línea

#### `getContentResolver()`

Obtiene una instancia del **ContentResolver** del sistema.

Este objeto es el **punto de entrada obligatorio** para comunicarse con cualquier Content Provider.

Desde pentesting:

* No hay validación aquí
* Si la llamada llega al Provider, el sistema asume que es legítima

---

#### `query(...)`

Llama a la operación **READ** del modelo CRUD.

Internamente:

* El ContentResolver localiza el Provider usando la URI
* Android invoca el método `query()` del Content Provider objetivo

Si el Provider no valida permisos correctamente, la consulta se ejecuta.

---

#### `UserDictionary.Words.CONTENT_URI`

Es la **URI que identifica el recurso** al que se quiere acceder.

Conceptualmente:

* Es similar a una URL
* Identifica una "tabla" o colección de datos

Ejemplo conceptual:

```
content://user_dictionary/words
```

En pentesting:

* Enumerar URIs es una técnica básica
* URIs predecibles suelen implicar exposición

---

#### `projection`

Define **qué columnas** se quieren obtener.

Ejemplo:

```java
String[] projection = {
    UserDictionary.Words.WORD,
    UserDictionary.Words.LOCALE
};
```

Desde un punto de vista ofensivo:

* Puedes intentar pedir columnas no documentadas
* Algunos Providers devuelven más datos de los esperados

---

#### `selectionClause`

Funciona como un **WHERE** en SQL.

Ejemplo:

```java
String selectionClause = UserDictionary.Words.LOCALE + "=?";
```

Errores típicos:

* Concatenar strings directamente
* No validar entradas

Esto puede llevar a **inyecciones lógicas** o filtrados bypassables.

---

#### `selectionArgs`

Son los valores que sustituyen los `?` del filtro.

Ejemplo:

```java
String[] selectionArgs = {"en_US"};
```

Ventaja:

* Previene SQL injection

Problema:

* Muchos desarrolladores no lo usan correctamente

---

#### `sortOrder`

Define el orden de los resultados.

Ejemplo:

```java
String sortOrder = UserDictionary.Words.WORD + " ASC";
```

Desde pentesting:

* Suele ser irrelevante
* Pero a veces permite inferir estructura interna

---

#### `cursor`

El resultado es un **Cursor**, que apunta a los datos devueltos.

Características:

* No contiene los datos directamente
* Permite recorrerlos fila a fila

Si puedes obtener un cursor válido:

> Ya has pasado todos los controles de seguridad del Provider.

---

## 🏗️ Implementación de un Content Provider

Todo Content Provider **hereda de la clase `ContentProvider`**:

```java
public class MyContentProvider extends ContentProvider {
    // Implementación de CRUD
}
```

### 🔍 Qué significa esto realmente

Al heredar de `ContentProvider`, el desarrollador está obligado a implementar métodos clave:

* `query()`
* `insert()`
* `update()`
* `delete()`

Cada uno de estos métodos es un **punto de entrada directo para un atacante**.

---

### Ejemplo simplificado de `query()`

```java
@Override
public Cursor query(Uri uri, String[] projection, String selection,
                    String[] selectionArgs, String sortOrder) {
    return database.query("users", projection, selection, selectionArgs,
                          null, null, sortOrder);
}
```

### Análisis de seguridad

* `uri`: ¿se valida qué recurso se pide?
* `projection`: ¿se filtran columnas sensibles?
* `selection`: ¿se concatena texto?
* `selectionArgs`: ¿se usan correctamente?

Si alguna de estas respuestas es "no": posible vulnerabilidad.

---

## 📄 Declaración en AndroidManifest.xml

El Content Provider debe declararse siempre en el manifest:

```xml
<provider
    android:name=".MyContentProvider"
    android:authorities="com.example.myapp.provider"
    android:exported="false" />
```

### 🔍 Explicación campo por campo

#### `android:name`

Clase Java que implementa el Provider.

Desde pentesting:

* Ayuda a identificar lógica interna

---

#### `android:authorities`

Define el **identificador global** del Provider.

Forma la base de todas las URIs:

```
content://com.example.myapp.provider/...
```

Si conoces este valor:

> Ya tienes medio exploit hecho.

---

#### `android:exported`

Controla quién puede acceder:

* `true`: cualquier app
* `false`: solo la app propietaria

Errores comunes:

* Providers exportados por defecto
* Confianza excesiva en que nadie los llamará

---

## 🏗️ Implementación de un Content Provider

Todo Content Provider **hereda de la clase `ContentProvider`**:

```java
public class MyContentProvider extends ContentProvider {
    // Implementación de CRUD
}
```

Esto obliga al desarrollador a implementar explícitamente:

* Qué ocurre al consultar datos
* Qué validaciones existen
* Qué permisos se comprueban

Errores comunes:

* No validar el caller
* No filtrar correctamente las consultas
* Confiar en que solo la app propia accederá

---

## 🖥️ Acceso mediante ADB

Los Content Providers pueden interactuarse directamente desde **ADB**, sin escribir código.

Esto permite:

* Enumerar datos
* Probar accesos no autorizados
* Confirmar impacto real

Desde pentesting, ADB es una de las herramientas más potentes para auditar Providers.

---

## 🎯 Mentalidad ofensiva: qué buscar

Checklist básica:

* Providers exportados
* Falta de permisos
* Lectura de información sensible
* Escritura o borrado no autorizado
* Filtros manipulables
* URIs predecibles

Un Content Provider vulnerable suele ser **explotable en minutos**.

---

## 🧠 Idea clave final

Un Content Provider **no es peligroso por sí mismo**.

Lo peligroso es:

* Exponerlo
* Confiar en exceso
* No validar quién accede

Para un pentester Android, entenderlos bien es obligatorio.
