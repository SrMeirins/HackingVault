# Acceso y Extracción de Contraseñas desde SYSVOL

SYSVOL es una carpeta compartida dentro del dominio de Active Directory que contiene scripts y políticas de grupo (Group Policies). En ocasiones, si tenemos acceso a SYSVOL, podemos obtener contraseñas cifradas que se encuentran en archivos de configuración de las políticas de grupo. Estas contraseñas pueden ser desencriptadas ya que Microsoft publicó la clave privada en su día.

## Localización de las Contraseñas Cifradas

Las contraseñas cifradas se encuentran en un archivo llamado `groups.xml`, ubicado en el directorio `Preferences` dentro de las políticas de grupo de la máquina.

Ejemplo de ruta donde se pueden encontrar las contraseñas cifradas:

```
replication/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/groups.xml
```

Dentro de este archivo, las contraseñas están almacenadas de manera cifrada.

## Desencriptado de las Contraseñas

Para obtener el texto claro de las contraseñas, podemos utilizar la herramienta `gpp-decrypt`, que permite desencriptar las contraseñas almacenadas en el archivo `groups.xml` de SYSVOL.

Ejemplo de uso de la herramienta `gpp-decrypt`:

```bash
gpp-decrypt groups.xml
```

Esta herramienta permitirá extraer las contraseñas en texto claro que están cifradas en el archivo de preferencias de las políticas de grupo.

**Nota**: Este tipo de acceso a SYSVOL generalmente requiere privilegios adecuados, por lo que tener acceso a este recurso de manera legítima o mediante un ataque es crucial para llevar a cabo la extracción de las contraseñas.
```
