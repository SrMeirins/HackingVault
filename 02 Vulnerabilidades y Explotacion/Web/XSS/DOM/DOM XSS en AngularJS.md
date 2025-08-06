# DOM XSS en AngularJS: Explicación Detallada

## Introducción a AngularJS

AngularJS es un framework de JavaScript desarrollado por Google para la creación de aplicaciones web dinámicas. Su principal característica es el **data binding** bidireccional, lo que significa que cualquier cambio en los datos del modelo se refleja automáticamente en la vista y viceversa. Además, AngularJS permite extender el HTML con directivas personalizadas y expresiones que facilitan la manipulación del DOM sin necesidad de manipulación directa con JavaScript.

## Importancia del atributo `ng-app`

Cuando en el `<body>` de una página web se encuentra el atributo:

```html
<body ng-app>
```

Esto indica que AngularJS ha inicializado una **aplicación Angular** dentro del cuerpo del documento. El `ng-app` actúa como punto de entrada para AngularJS y define el **scope** donde se pueden evaluar las expresiones de AngularJS, permitiendo la ejecución de código dentro de `{{ }}`.

## Restricción de funciones como `alert()` o `print()`

AngularJS restringe el acceso directo a funciones nativas de JavaScript como `alert()` o `print()`. Esto se debe a que las expresiones dentro de `{{ }}` solo pueden evaluar operaciones matemáticas básicas y acceso a variables del **scope** de AngularJS. La razón principal de esta limitación es **seguridad**, evitando la ejecución de código malicioso directamente dentro de expresiones Angular.

Sin embargo, es posible eludir esta restricción utilizando técnicas avanzadas de JavaScript, como el uso del constructor `Function`.

## Análisis Inicial del XSS

Se realiza una prueba básica con la siguiente inyección:

```html
<img src=x onerror=alert(document.origin)/>
```

No se genera una alerta, y al inspeccionar el código fuente, se observa que los corchetes angulares (`< >`) están codificados:

```html
<h1>0 search results for '&lt;img src=x onerror=alert(document.origin)/&gt;'</h1>
```

Además, en el `<head>` de la página se encuentra la inclusión de AngularJS:

```html
<script type="text/javascript" src="/resources/js/angular_1-7-7.js"></script>
```

Dado que AngularJS está presente y `ng-app` está en el `body`, se pueden evaluar expresiones dentro de `{{ }}`:

```html
{{ 21 + 21 }}
```

Esto devuelve **42**, confirmando que la evaluación de expresiones está habilitada.

## Uso de `.constructor` y `Function` en JavaScript

En JavaScript, `Function` es un constructor especial que permite crear funciones dinámicamente. La sintaxis básica es:

```javascript
var func = new Function('return 42');
console.log(func()); // Devuelve 42
```

De manera similar, en JavaScript todas las funciones tienen un atributo `.constructor`, que se puede usar para generar nuevas funciones de manera dinámica. Por ejemplo:

```javascript
alert.constructor('alert("XSS")')()
```

Aquí, `alert.constructor` devuelve `Function`, lo que significa que podemos crear una nueva función que ejecuta `alert("XSS")` y llamarla inmediatamente con `()`. Esto permite ejecutar código arbitrario sin necesidad de invocar directamente `alert()` en el código fuente.

## Aplicación en AngularJS: Explotación de `$watch`

En AngularJS, `$watch` es un método del **scope** que permite monitorear cambios en las variables. Dado que `$watch` es una función, podemos acceder a su `constructor` y aprovecharlo para ejecutar código arbitrario.

Ejecutamos la siguiente inyección dentro de una expresión Angular:

```html
{{ $watch.constructor('alert("XSS")')() }}
```

### Explicación del Payload:
1. `$watch.constructor` obtiene el constructor de la función `$watch`, que es `Function`.
2. `constructor('alert("XSS")')` crea una nueva función que ejecuta `alert("XSS")`.
3. `()`, al final, llama a la función recién creada, lo que provoca la ejecución del `alert()`.

Esto confirma la explotación de **DOM XSS en AngularJS**, a pesar de las restricciones impuestas por el framework.

## Conclusión

El uso de AngularJS en una web puede abrir vectores de ataque para **DOM XSS**, incluso cuando los caracteres peligrosos están siendo codificados en HTML. Aprovechando la ejecución de expresiones y el `Function` constructor, es posible evadir restricciones y ejecutar código arbitrario en el contexto de la víctima. 

Este tipo de ataque es especialmente peligroso en aplicaciones que no deshabilitan las expresiones de AngularJS (`$interpolateProvider`), ya que permite a un atacante ejecutar código en el navegador de la víctima sin necesidad de inyecciones tradicionales de `<script>`.

