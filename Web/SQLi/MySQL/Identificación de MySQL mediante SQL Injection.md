### **Identificación de MySQL mediante SQL Injection**  

Estamos probando SQL Injection en una aplicación web que filtra productos por categoría. La petición vulnerable se realiza a través de una URL como esta:  

```
https://target.com/filter?category=Gifts
```
El parámetro `category` se inserta directamente en una consulta SQL, lo que permite inyectar código malicioso y extraer información de la base de datos.  

#### **Paso 1: Determinar el número de columnas con `ORDER BY`**  
Para encontrar el número de columnas, probamos con valores altos hasta obtener un error y luego reducimos hasta que la consulta sea válida:  
```sql
Gifts' ORDER BY 10--  
Gifts' ORDER BY 5--  
Gifts' ORDER BY 3--  
Gifts' ORDER BY 2-- ✅ (Éxito)
```
Cuando la consulta devuelve una respuesta válida, significa que la consulta original tiene **2 columnas**.  

#### **Paso 2: Identificar columnas de tipo texto**  
Usamos `UNION SELECT` con valores conocidos para ver qué columnas aceptan texto:  
```sql
Gifts' UNION SELECT 'test', NULL--  
```
Si `test` aparece en la respuesta, la primera columna acepta texto.  

#### **Paso 3: Obtener la versión de MySQL**  
Una vez confirmadas las columnas, extraemos la versión del servidor con:  
```sql
Gifts' UNION SELECT version(), NULL--  
```
- `version()` devuelve la versión exacta de MySQL.  
- Si obtenemos un resultado válido, confirmamos que la base de datos es **MySQL** y podemos continuar con ataques más avanzados.
