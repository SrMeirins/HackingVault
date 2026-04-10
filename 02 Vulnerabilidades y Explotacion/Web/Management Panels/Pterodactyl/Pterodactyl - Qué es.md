# ¿Qué es Pterodactyl?

**Pterodactyl** es un panel de gestión de servidores de juegos de código abierto, escrito en **PHP (Laravel)** con frontend en React. Permite crear, administrar y monitorizar servidores de juegos (Minecraft, CS:GO, Rust, etc.) a través de una interfaz web.

## Stack tecnológico

| Componente | Tecnología |
|------------|------------|
| Backend | PHP / Laravel |
| Frontend | React |
| Base de datos | MySQL / MariaDB |
| Web server | nginx |
| Daemon | Wings (Go) — gestiona los contenedores Docker |

## Arquitectura típica

- **Panel** (`panel.dominio.htb`) — Interfaz web de administración. Aquí viven las vulnerabilidades más interesantes.
- **Wings** — Daemon que corre en los nodos y se comunica con el panel vía API. Gestiona los contenedores donde corren los servidores de juegos.
- **Play** (`play.dominio.htb`) — Subdominio público orientado a los jugadores.

## Por qué es relevante en pentesting

- Expone una interfaz web con autenticación accesible desde fuera.
- Al ser Laravel, tiene vectores típicos: `.env` con credenciales en claro, `APP_KEY` para forjar sesiones, acceso a MariaDB.
- Versiones antiguas han presentado vulnerabilidades pre-auth graves (ej: CVE-2025-49132).
- Suele correr con permisos elevados al interactuar con Docker/Wings.

## Referencias

- Repositorio oficial: <https://github.com/pterodactyl/panel>
- Web oficial: <https://pterodactyl.io>
