# **Fuzzing de Plugins en WordPress con WFUZZ**  

El fuzzing de plugins en **WordPress** permite identificar complementos instalados en un sitio web probando diferentes nombres de plugins en las rutas del servidor. Esto es útil para descubrir vulnerabilidades en plugins desactualizados o mal configurados.  

📌 **Herramienta utilizada:**  
🔗 [WFUZZ - Web Fuzzer](https://github.com/xmendez/wfuzz)  

---

## **¿Cómo Funciona el Ataque?**  

1. Se utiliza un diccionario con nombres de plugins de WordPress.  
2. Se realizan solicitudes HTTP a la URL del sitio objetivo reemplazando **FUZZ** con cada nombre de plugin.  
3. Se identifican respuestas con códigos HTTP distintos a `404` (No encontrado), lo que sugiere que el plugin existe.  

---

## **Ejemplo de Uso con WFUZZ**  

Para realizar fuzzing de plugins en WordPress con `WFUZZ`, usamos el siguiente comando:  

```bash
wfuzz -c --hc=404 -w /usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt -u http://tenten.htb/FUZZ -t 200
```

### **Explicación de los argumentos:**  
- **`-c`** → Muestra la salida en color.  
- **`--hc=404`** → Oculta respuestas con código HTTP `404` (páginas no encontradas).  
- **`-w /usr/share/seclists/.../wp-plugins.fuzz.txt`** → Diccionario con nombres de plugins de WordPress.  
- **`-u http://tenten.htb/FUZZ`** → URL del objetivo con el marcador `FUZZ` para reemplazar con los nombres del diccionario.  
- **`-t 200`** → Usa 200 hilos para acelerar el proceso.  
