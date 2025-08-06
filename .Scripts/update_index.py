import os

# --- Configuración ---
REPO_ROOT = '..'
README_FILE = os.path.join(REPO_ROOT, 'README.md')
EXCLUDE_DIRS = ['.git', '.github', '.scripts']
EXCLUDE_FILES = ['README.md', 'update_index.py']

INDEX_START_MARKER = '%%INDEX_START%%'
INDEX_END_MARKER = '%%INDEX_END%%'

def get_files_and_dirs(root_dir):
    """Recorre el directorio y devuelve una estructura anidada."""
    tree = {}
    
    # Ordenar los directorios principales (01, 02...)
    sorted_root_dirs = sorted([d for d in os.listdir(root_dir) if os.path.isdir(os.path.join(root_dir, d)) and d not in EXCLUDE_DIRS])

    for dir_name in sorted_root_dirs:
        dir_path = os.path.join(root_dir, dir_name)
        tree[dir_name] = {'files': [], 'dirs': get_files_and_dirs(dir_path)}

    # Ordenar los archivos dentro del directorio actual
    sorted_files = sorted([f for f in os.listdir(root_dir) if os.path.isfile(os.path.join(root_dir, f)) and f.endswith('.md') and f not in EXCLUDE_FILES])
    tree['files'] = sorted_files
    
    return tree

def generate_markdown_recursive(dir_structure, root_path, level=0):
    """Genera el texto del índice en Markdown de forma recursiva."""
    lines = []
    
    # Primero los directorios
    for dir_name, content in sorted(dir_structure.items()):
        if dir_name == 'files':
            continue
        
        dir_path = os.path.join(root_path, dir_name)
        
        lines.append(f"<details>")
        # El enlace del directorio principal
        dir_link = dir_path.replace('\\', '/').replace(' ', '%20')
        lines.append(f"<summary><strong>{'  ' * level}📂 [{dir_name}]({dir_link})</strong></summary>\n")
        
        # Procesar subdirectorios y archivos de forma recursiva
        lines.extend(generate_markdown_recursive(content, dir_path, level + 1))
        
        # Procesar archivos en este directorio
        for filename in content.get('files', []):
            file_path = os.path.join(dir_path, filename)
            link_text = os.path.splitext(filename)[0]
            relative_path = os.path.relpath(file_path, start='.').replace('\\', '/')
            encoded_path = relative_path.replace(' ', '%20')
            lines.append(f"{'  ' * (level + 2)}* 📄 [{link_text}]({encoded_path})")

        lines.append(f"</details>")

    return lines

def generate_index(root_dir):
    """Función principal para generar todo el índice."""
    
    # Obtenemos solo los directorios del primer nivel para iniciar
    top_level_dirs = sorted([d for d in os.listdir(root_dir) if os.path.isdir(os.path.join(root_dir, d)) and d not in EXCLUDE_DIRS])
    
    final_lines = []
    for dir_name in top_level_dirs:
        dir_path = os.path.join(root_dir, dir_name)
        
        # Estructura para el directorio de primer nivel
        dir_structure = {
            dir_name: get_files_and_dirs(dir_path)
        }
        
        # Añadir archivos que puedan estar en el directorio de primer nivel (01 Reconocimiento, etc.)
        dir_structure[dir_name]['files'] = sorted([f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f)) and f.endswith('.md') and f not in EXCLUDE_FILES])

        final_lines.extend(generate_markdown_recursive(dir_structure, root_dir))
        
    return "\n".join(final_lines)

def update_readme(readme_path, index_content):
    """Actualiza el README.md con el nuevo índice entre los marcadores."""
    try:
        with open(readme_path, 'r', encoding='utf-8') as f:
            content = f.read()

        start_marker_pos = content.find(INDEX_START_MARKER)
        end_marker_pos = content.find(INDEX_END_MARKER)

        if start_marker_pos == -1 or end_marker_pos == -1:
            print(f"🚨 Error: No se encontraron los marcadores '{INDEX_START_MARKER}' o '{INDEX_END_MARKER}' en el README.md")
            return

        new_content = (
            content[:start_marker_pos + len(INDEX_START_MARKER)] +
            '\n\n' +
            index_content +
            '\n\n' +
            content[end_marker_pos:]
        )

        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        print("✅ ¡Índice desplegable actualizado correctamente en README.md!")

    except FileNotFoundError:
        print(f"🚨 Error: El archivo {readme_path} no fue encontrado.")

if __name__ == "__main__":
    print("🚀 Generando índice desplegable para el HackingVault...")
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    index = generate_index(REPO_ROOT)
    update_readme(README_FILE, index)