### **UNION SQL Injection Attack: Listar el contenido de la base de datos en bases de datos no Oracle**

Este ataque es de tipo **Union-Based SQL Injection**, donde usamos la cláusula `UNION` para combinar los resultados de la consulta inyectada con los resultados de la consulta original de la aplicación. A través de este enfoque, podemos extraer información sensible de la base de datos. A continuación, se describe el proceso y los payloads que permiten obtener el contenido de la base de datos.

---

#### **1. Determinar el número de columnas con `ORDER BY`**  
```sql
Pets' ORDER BY 2--  
```
- **Contexto**: La consulta original probablemente esté utilizando una cláusula `ORDER BY` para ordenar los resultados según una columna.
- **Explicación**:  
  - El parámetro `category` en la URL se inyecta con `' ORDER BY 2--`.
  - `ORDER BY 2` intenta ordenar los resultados por la **segunda columna**.
  - Si la consulta devuelve un **resultado exitoso**, significa que hay **al menos 2 columnas**.
  - Si obtenemos un error (por ejemplo, "Unknown column '2'"), probamos con valores mayores hasta obtener una respuesta válida.
  - **Objetivo**: Determinar cuántas columnas tiene la consulta original para poder continuar con una inyección exitosa.

---

#### **2. Verificar columnas de tipo texto**
```sql
Pets' UNION SELECT 'test', 'test'--  
```
- **Contexto**: Queremos verificar qué columnas permiten datos tipo texto.
- **Explicación**:  
  - Aquí estamos usando `UNION SELECT` para intentar combinar el resultado original con nuestros propios valores: `'test', 'test'`.
  - `UNION SELECT` sirve para combinar los resultados de nuestra consulta inyectada con los resultados de la consulta original.
  - Si la aplicación **muestra "test"** en la respuesta, significa que **ambas columnas aceptan texto**.
  - Si la consulta falla, probamos con diferentes combinaciones de `NULL` y valores de texto para ver en qué columnas se puede inyectar texto.
  - **Objetivo**: Confirmar que las columnas en la consulta original permiten valores de texto y así poder hacer la inyección de datos.

---

#### **3. Enumerar las bases de datos disponibles**
```sql
Pets' UNION SELECT schema_name, NULL FROM information_schema.schemata--  
```
- **Contexto**: Ahora que conocemos las columnas, queremos listar las bases de datos disponibles en el servidor.
- **Explicación**:  
  - `information_schema.schemata` es una vista del sistema en MySQL que contiene los nombres de las bases de datos en el servidor.
  - `schema_name` es el campo que contiene el nombre de la base de datos.
  - **Objetivo**: Obtener una lista de las bases de datos disponibles en el servidor.

---

#### **4. Listar las tablas dentro de una base de datos específica**
```sql
Pets' UNION SELECT table_name, NULL FROM information_schema.tables WHERE table_schema = 'public'--  
```
- **Contexto**: Queremos listar las tablas dentro de una base de datos específica.
- **Explicación**:  
  - `information_schema.tables` es una vista que contiene los nombres de las tablas en la base de datos seleccionada.
  - Usamos `WHERE table_schema = 'public'` para filtrar las tablas dentro de la base de datos **public**.
  - **Objetivo**: Enumerar las tablas dentro de la base de datos seleccionada.

---

#### **5. Obtener las columnas de una tabla específica**
```sql
Pets' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'users_kovytc'--  
```
- **Contexto**: Ahora que tenemos las tablas, queremos saber qué columnas existen en una tabla específica.
- **Explicación**:  
  - `information_schema.columns` contiene la información sobre las columnas de las tablas.
  - `column_name` es el campo que contiene el nombre de las columnas.
  - Usamos `WHERE table_schema = 'public' AND table_name = 'users_kovytc'` para filtrar por la tabla `users_kovytc`.
  - **Objetivo**: Enumerar las columnas de una tabla específica.

---

#### **6. Obtener la contraseña de un usuario específico**
```sql
Pets' UNION SELECT password_zczmqp, NULL FROM public.users_kovytc WHERE username_mqnupt = 'administrator'--  
```
- **Contexto**: Queremos obtener la contraseña de un usuario específico.
- **Explicación**:  
  - `password_zczmqp` es el campo que almacena las contraseñas.
  - Usamos `WHERE username_mqnupt = 'administrator'` para obtener la contraseña del usuario **administrator**.
  - **Objetivo**: Extraer la contraseña de un usuario objetivo.

---

#### **7. Obtener todas las credenciales (usuario y contraseña)**
```sql
Pets' UNION SELECT username_mqnupt || ':' || password_zczmqp, NULL FROM public.users_kovytc--  
```
- **Contexto**: Queremos extraer todas las credenciales (usuario y contraseña) almacenadas en la base de datos.
- **Explicación**:  
  - `username_mqnupt` es el campo que contiene los nombres de usuario, y `password_zczmqp` contiene las contraseñas.
  - Usamos el operador de concatenación `||` para combinar los valores de `username_mqnupt` y `password_zczmqp` en un solo resultado, separándolos con `:` (esto crea una salida como `usuario:contraseña`).
  - **Objetivo**: Extraer todas las credenciales almacenadas.

---

Este ataque **Union-Based SQL Injection** es válido no solo para **MySQL**, sino también para **PostgreSQL**, ya que ambos sistemas permiten el acceso a metadatos como las bases de datos, tablas y columnas mediante las vistas del sistema.
