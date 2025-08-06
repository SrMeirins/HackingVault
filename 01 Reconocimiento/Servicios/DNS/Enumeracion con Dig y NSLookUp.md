# **Enumeración y Análisis DNS (`dig` & `nslookup`)**

Al encontrar el puerto 53 (DNS) abierto, la primera fase del reconocimiento consiste en extraer la máxima información posible. Esta guía detalla el proceso, desde los intentos iniciales hasta el análisis profundo de las respuestas.

## 1\. El Primer Paso Obligatorio: Intento de Transferencia de Zona (AXFR)

Siempre debes empezar por aquí. Una transferencia de zona exitosa te entrega todos los registros DNS de un dominio, dándote un mapa completo de la red.

#### Comando

```bash
dig @<IP_Servidor_DNS> <dominio> axfr
```

#### Ejemplo de Ejecución

```bash
dig @10.10.10.224 realcorp.htb axfr
```

**Resultado:**

```
; <<>> DiG 9.20.9-1-Debian <<>> @10.10.10.224 realcorp.htb axfr
; Transfer failed.
```

  * **Análisis**: El fallo en la transferencia es el resultado más común y significa que el servidor está configurado de forma segura contra esta técnica. Esto nos obliga a pasar a métodos de enumeración más activos.

## 2\. Consulta de Registros Específicos y Análisis de Salida

Aquí es donde `dig` demuestra su superioridad sobre `nslookup`.

### ¿Por qué `dig` parece dar "más" información que `nslookup`?

La diferencia fundamental es cómo cada herramienta presenta la respuesta del servidor:

  * **`dig`**: Te muestra la respuesta DNS completa, dividida en secciones (`QUESTION`, `ANSWER`, `AUTHORITY`, `ADDITIONAL`). Es transparente y te da todo el contexto.
  * **`nslookup`**: Simplifica la salida, mostrando principalmente la sección `ANSWER`. Si esa sección está vacía, a menudo concluye con un `No answer`, ocultando información contextual valiosa que `dig` sí revela, como la sección `AUTHORITY`.

### Interpretando la Salida de `dig`

| Sección | Descripción |
| :--- | :--- |
| **`QUESTION`** | Lo que le preguntaste al servidor. Útil para verificar tu consulta. |
| **`ANSWER`** | La respuesta directa. Si pides un registro y existe, aparecerá aquí. **Si está vacía, es un hallazgo**: significa que no existe un registro de ese tipo para tu consulta. |
| **`AUTHORITY`** | La "prueba de autoridad". Si la sección `ANSWER` está vacía, el servidor puede usar esta sección para decir: "No tengo la respuesta, pero soy el servidor autoritativo para este dominio". Usualmente, muestra un registro `SOA` (Start of Authority), confirmando que estás hablando con el servidor correcto. |
| **`ADDITIONAL`** | "Registros de pegamento" (Glue records). Información extra que el servidor te proporciona para ahorrarte consultas. Por ejemplo, al darte un `NS`, puede añadir el registro `A` (la IP) de ese servidor de nombres. |

### Análisis Práctico de tus Consultas

#### Consulta de Registros NS (Name Server)

```bash
dig @10.10.10.224 realcorp.htb ns
```

  * **`ANSWER SECTION`**: `realcorp.htb. IN NS ns.realcorp.htb.`
      * **Análisis**: El servidor de nombres (`NS`) para `realcorp.htb` es un host llamado `ns.realcorp.htb`.
  * **`ADDITIONAL SECTION`**: `ns.realcorp.htb. IN A 10.197.243.77`
      * **Análisis**: El servidor nos adelanta la IP (`A` record) de `ns.realcorp.htb`, que es `10.197.243.77`.

`nslookup` también mostró esto porque existía una respuesta directa en la sección `ANSWER`.

#### Consultas sin Respuesta Directa (`A` y `MX`)

```bash
dig @10.10.10.224 realcorp.htb
```

  * **`ANSWER SECTION: 0`**
      * **Análisis**: No hay un registro `A` para el dominio raíz `realcorp.htb`. Esto es normal y no significa un error. Los servicios suelen estar en subdominios.
  * **`AUTHORITY SECTION`**: `realcorp.htb. IN SOA ...`
      * **Análisis**: El servidor responde: "No tengo un registro `A` para `realcorp.htb`, pero confirmo que soy la autoridad para este dominio".

Este es el escenario donde `nslookup` te dio `*** Can't find realcorp.htb: No answer`. Simplemente omitió la valiosa información de la sección `AUTHORITY`.

## 3\. Conclusiones y Siguientes Pasos

1.  **Usa `dig` como herramienta principal**: Su salida detallada es crucial para un análisis preciso.
2.  **Una respuesta sin sección `ANSWER` es información, no un error**: Te indica que ese registro específico no existe.
3.  **El registro `SOA` es tu amigo**: Confirma que estás consultando al servidor DNS correcto y autoritativo para el dominio.
4.  **Siguiente paso lógico**: Dado que el dominio raíz no resuelve y la transferencia de zona falló, el camino a seguir es la **fuerza bruta de subdominios** para encontrar los hosts que sí tienen servicios (`www`, `api`, `vpn`, `dev`, `wpad`, etc.).