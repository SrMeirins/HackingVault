## MongoDB

---

### Acceso Básico

* **Puerto por defecto**: `27017`
* **Conexión**: `mongo --port 27017` (si estás en la máquina local).

---

### Comandos de Shell MongoDB

Una vez dentro de la shell `mongo`:

* **`show dbs`**: Lista todas las bases de datos.
* **`use [nombre_db]`**: Cambiar a una base de datos específica.
    * **Ej**: `use admin`
* **`show collections`**: Lista las colecciones en la DB actual.
* **`db.getCollectionNames()`**: Devuelve solo los nombres de las colecciones.
* **`db.getCollectionInfos()`**: Información detallada de las colecciones.
* **`db.nombreColeccion.find()`**: Muestra todos los documentos de una colección.
    * **Ej**: `db.users.find()`
* **`db.nombreColeccion.find({}, { campo1: 1, campo2: 1, _id: 0 })`**: Filtrar campos específicos.
    * **Ej**: `db.admin.find({}, { name: 1, x_shadow: 1, _id: 0 })`

---

### Modificación de Datos (Ejemplo)

* **Actualizar un campo**:

    ```javascript
    db.admin.update(
        {"_id": ObjectId("61ce278f46e0fb0012d47ee4")},
        {$set: {"x_shadow": "$6$pJNmH9kTv2t9tuW9$hrZXVfaMe1EE45EMYHRIjx5mJi8ZMOtjBJ.0JcPFWAS6hvy7fOxrReAtXUT5omfeStn18i8znCcNvsf4WL.yU/"}}
    )
    ```

    * **`update()`**: Método para actualizar.
    * **`{"_id": ObjectId(...)`**: Criterio para encontrar el documento.
    * **`{$set: {campo: valor}}`**: Operador para establecer un nuevo valor para el campo.