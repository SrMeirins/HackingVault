## 🧠 Enumeración de Subdominios con Gobuster (Modo VHost)

* **Gobuster**: una herramienta escrita en Go, usada para hacer fuerza bruta en URIs, directorios, subdominios, buckets de S3, etc.
* En este caso, usamos el modo **VHost**, ideal cuando queremos descubrir subdominios en entornos con **Name-Based Virtual Hosting** (por ejemplo, máquinas de Hack The Box).

---

### 🎯 Objetivo

Descubrir subdominios (vhosts) que puedan estar configurados en el mismo servidor web. A menudo, estos subdominios pueden revelar paneles de administración, entornos de staging o servicios expuestos que no están visibles en el dominio principal.

---

### 📌 Comando utilizado

```bash
gobuster vhost -w /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt -u http://planning.htb -t 50 --append-domain
```

---

### 📖 Explicación del comando

| Opción                                                         | Descripción                                                                                                                                         |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vhost`                                                        | Modo de Gobuster para fuerza bruta de virtual hosts (subdominios).                                                                                  |
| `-w /usr/share/SecLists/Discovery/DNS/combined_subdomains.txt` | Lista de palabras para probar como posibles subdominios. Se recomienda usar una lista extensa como esta para mejores resultados.                    |
| `-u http://planning.htb`                                       | URL base del dominio objetivo. Este será el dominio raíz al cual se le intentarán anexar subdominios.                                               |
| `-t 50`                                                        | Número de hilos (threads) simultáneos. Aumentar este número acelera el escaneo, pero puede generar más ruido o ser bloqueado.                       |
| `--append-domain`                                              | Gobuster agregará automáticamente el dominio (`planning.htb`) al final de cada palabra de la lista, formando subdominios como `admin.planning.htb`. |

---

### 🧪 Ejemplo de salida

```text
Found: dev.planning.htb (Status: 200)
Found: admin.planning.htb (Status: 403)
Found: staging.planning.htb (Status: 302)
```

Esto indica que existen otros subdominios virtuales configurados, y podríamos probarlos manualmente en el navegador o con otras herramientas.

---

### 🧩 Recomendaciones

* Añade los subdominios encontrados al archivo `/etc/hosts` si estás en una red cerrada o máquina virtual (como en HTB), ya que la resolución DNS puede no funcionar automáticamente.

  ```bash
  echo "10.10.11.123 dev.planning.htb admin.planning.htb staging.planning.htb" | sudo tee -a /etc/hosts
  ```

---

### 🚩 Casos útiles

* HackTheBox y otras plataformas CTF donde el servidor puede tener múltiples virtual hosts configurados.
* Aplicaciones reales donde el uso de virtual hosting es común para separar entornos (dev, test, staging, prod).

---

### 📚 Referencias

* [Gobuster GitHub](https://github.com/OJ/gobuster)
* [SecLists - DNS Subdomain Wordlists](https://github.com/danielmiessler/SecLists)