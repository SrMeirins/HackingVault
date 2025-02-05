# Montaje de Recursos Compartidos en Linux

En situaciones en las que un directorio compartido es muy grande, hay retrasos o necesitamos realizar un análisis detallado de la estructura de archivos (por ejemplo, utilizando el comando `tree` o filtrando por un archivo específico), podemos montar el recurso SMB en un directorio local para tener acceso completo a él.

## Montaje de un Recurso Compartido

Para montar un recurso compartido en Linux, primero debemos crear un directorio donde se montará el recurso, y luego usar el comando `mount` para montarlo como un recurso CIFS.

1. **Crear un directorio en `/mnt`:**

   ```bash
   mkdir /mnt/montura
   ```

2. **Montar el recurso compartido en el directorio:**

   ```bash
   mount -t cifs "//10.10.10.103/Department Shares" /mnt/montura
   ```

   - **`-t cifs`**: Especifica que se montará un recurso CIFS (Common Internet File System).
   - **`//10.10.10.103/Department Shares`**: Dirección del recurso compartido, en formato `//<ip>/<recurso>`.
   - **`/mnt/montura`**: Ruta donde se montará el recurso.

   - **Nota**: Si el recurso no requiere autenticación, se puede dejar la contraseña en blanco para una NULL Session, simplemente presionando `Enter`.

3. **Instalar el paquete necesario (si es necesario):**

   Asegúrate de que el paquete `cifs-utils` esté instalado para evitar errores durante el montaje. Si no está instalado, puedes instalarlo con el siguiente comando:

   ```bash
   sudo apt-get install cifs-utils
   ```

## Desmontaje del Recurso Compartido

Cuando hayas terminado de trabajar con el recurso, puedes desmontarlo utilizando el comando `umount`:

```bash
umount /mnt/montura
```

Este comando desconectará el recurso compartido y liberará el directorio `/mnt/montura`.
