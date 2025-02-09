### **Identificación de Oracle mediante SQL Injection**  

Estamos probando SQL Injection en una aplicación web que filtra productos por categoría. La petición vulnerable se realiza a través de una URL como la siguiente:  

```
https://target.com/filter?category=Gifts
```
El parámetro `category` se inserta directamente en la consulta SQL, lo que permite inyectar código malicioso y extraer información de la base de datos.  

#### **Paso 1: Verificar Oracle y el número de columnas**  
Interceptamos la petición con Burp Suite y probamos si la base de datos es Oracle utilizando la tabla especial `dual`:  
```sql
Gifts' UNION SELECT 'Oracle Detected', NULL FROM dual--
```
- Si obtenemos una respuesta válida, confirmamos que **Oracle es el motor de base de datos**.  
- Si hay error, ajustamos el número de columnas hasta encontrar la combinación correcta.  

Para verificar cuántas columnas devuelve la consulta y si aceptan texto, probamos:  
```sql
Gifts' UNION SELECT 'abc', 'def' FROM dual--
```
Si no hay error, significa que la consulta original devuelve **dos columnas de tipo texto**.  

#### **Paso 2: Obtener la versión de Oracle**  
Una vez identificadas las columnas, extraemos la versión con:  
```sql
Gifts' UNION SELECT banner, NULL FROM v$version--
```
- `v$version` es una vista exclusiva de Oracle con detalles del sistema.  
- `banner` nos muestra la versión exacta de la base de datos.  

Si obtenemos un resultado, confirmamos que estamos en **Oracle** y podemos planear ataques más avanzados.
