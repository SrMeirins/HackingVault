import os
import urllib.parse

# --- Configuración ---
REPO_ROOT = '..'
README_FILE = os.path.join(REPO_ROOT, 'README.md')
EXCLUDE_DIRS = ['.git', '.github', '.Scripts', '.obsidian']
EXCLUDE_FILES = ['README.md']

# --- Marcadores (Visibles en editor, invisibles en GitHub) ---
INDEX_START_MARKER = '[//]: # (HACKING_VAULT_INDEX_START)'
INDEX_END_MARKER = '[//]: # (HACKING_VAULT_INDEX_END)'

def generate_index(root_dir):
    """Genera el texto del índice en formato de lista Markdown."""
    markdown_lines = []
    
    for dirpath, dirnames, filenames in os.walk(root_dir, topdown=True):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        dirnames.sort()

        level = dirpath.replace(root_dir, '').count(os.sep)
        
        if dirpath == root_dir:
            continue

        indent = '  ' * (level - 1)
        dir_name = os.path.basename(dirpath)
        
        markdown_lines.append(f"{indent}* **📂 {dir_name}**")
        
        filenames.sort()
        for filename in filenames:
            if filename.endswith('.md') and filename not in EXCLUDE_FILES:
                link_text = os.path.splitext(filename)[0]
                relative_path = os.path.relpath(os.path.join(dirpath, filename), start=REPO_ROOT).replace('\\', '/')
                encoded_path = urllib.parse.quote(relative_path)
                
                file_indent = '  ' * level
                markdown_lines.append(f"{file_indent}  * 📄 [{link_text}]({encoded_path})")

    return "\n".join(markdown_lines)

def update_readme(readme_path, index_content):
    """Actualiza el README.md con el nuevo índice."""
    try:
        with open(readme_path, 'r', encoding='utf-8') as f:
            content = f.read()

        start_marker_pos = content.find(INDEX_START_MARKER)
        end_marker_pos = content.find(INDEX_END_MARKER)

        if start_marker_pos == -1 or end_marker_pos == -1:
            print(f"🚨 Error: No se encontraron los marcadores en el README.md.")
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
        
        print("✅ ¡Índice de lista completa actualizado correctamente en README.md!")

    except FileNotFoundError:
        print(f"🚨 Error: El archivo {readme_path} no fue encontrado.")

if __name__ == "__main__":
    print("🚀 Generando índice para el HackingVault...")
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    index = generate_index(REPO_ROOT)
    # --- LÍNEA CORREGIDA ---
    update_readme(README_FILE, index)
