# **Ataque de Fuerza Bruta a OpenSSL (Cifrado con Contraseña)**  

Este ataque permite descifrar archivos cifrados con **OpenSSL** cuando no se conoce ni la contraseña ni el algoritmo de cifrado utilizado. Se basa en un ataque de fuerza bruta utilizando una herramienta en Python que identifica el algoritmo y prueba combinaciones hasta descifrar el archivo.  

📌 **Herramienta utilizada:**  
🔗 [Brute.py - Fuerza bruta a OpenSSL](<inserta_aquí_el_link>)  

---

## **¿Cómo Funciona el Ataque?**  

1. OpenSSL permite cifrar archivos con contraseñas mediante diversos algoritmos.  
2. Cuando un archivo está cifrado de esta manera, su encabezado indica que fue cifrado con **OpenSSL (salted password, base64 encoded)**.  
3. La herramienta **brute.py** en Python puede analizar el archivo y detectar automáticamente el algoritmo utilizado.  
4. Luego, realiza un ataque de fuerza bruta utilizando un diccionario de contraseñas.  
5. Si la contraseña está en la lista, el script descifrará el archivo y mostrará su contenido.  

---

## **Ejemplo de Uso con brute.py**  

Para utilizar esta herramienta en **Python 2**, ejecutamos el siguiente comando:  

```bash
python2 brute.py /usr/share/wordlists/rockyou.txt ciphers.txt ../../nmap/drupal.txt.enc 2>/dev/null
```

### **Explicación de los argumentos:**  
- **`brute.py`** → Script que ejecuta el ataque de fuerza bruta.  
- **`/usr/share/wordlists/rockyou.txt`** → Diccionario de contraseñas comúnmente usadas.  
- **`ciphers.txt`** → Archivo con una lista de posibles algoritmos de cifrado soportados.  
- **`../../nmap/drupal.txt.enc`** → Archivo cifrado que queremos descifrar.  
- **`2>/dev/null`** → Suprime mensajes de error innecesarios.  
