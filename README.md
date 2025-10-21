<div align="center">
    # �LeuProtect Library 🛡️



**One-line C++ protection for Windows executables**

*Protección C++ para ejecutables Windows*

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![C++](https://img.shields.io/badge/C++-17-orange)

</div>

## 🌟 **About | Acerca de**

**LeuProtect Library** is a lightweight, powerful C++ library designed to protect your Windows executables from reverse engineering, debugging, and memory scanning with just one function call.

**LeuProtect Library** es una librería C++ ligera y poderosa diseñada para proteger tus ejecutables Windows de ingeniería inversa, debugging y escaneo de memoria con una sola llamada de función.

```cpp
#include "protection.h"

int main() {
    LeuProtect::Initialize();  // That's it! | ¡Eso es todo!

  // The rest of your beautiful code
  // El resto de tu hermoso código
}
```

---

## 🚀 Quick Start | Inicio Rápido

**English Version**

**Add files to your project**

```
📁 YourProject/
├── protection.h
├── protection.cpp
└── main.cpp
```

**Include and initialize**

```cpp
#include "protection.h"

int main() {
    LeuProtect::Initialize();  // Protection activated!

    // Your application code
}
```

**Versión en Español**

**Agrega los archivos a tu proyecto**

```
📁 TuProyecto/
├── protection.h
├── protection.cpp
└── main.cpp
```

**Incluye e inicializa**

```cpp
#include "protection.h"

int main() {
    LeuProtect::Initialize();  // ¡Protección activada!

    // Tu código de aplicación
}
```

---

## 🛡️ Features | Características

### Protection Features | Características de Protección

| Feature | Description | Descripción |
|---|---:|---|
| Anti-Debugging | Detects and prevents debuggers like x64dbg, OllyDbg, Cheat Engine | Detecta y previene debuggers como x64dbg, OllyDbg, Cheat Engine |
| Memory Protection | Uses VirtualProtect to secure memory regions | Usa VirtualProtect para proteger regiones de memoria |
| Code Obfuscation | Runtime code modification to hinder static analysis | Modificación de código en tiempo de ejecución para dificultar análisis estático |
| PE Header Protection | Secures and obfuscates PE headers | Protege y ofusca headers PE |
| Continuous Monitoring | Real-time protection monitoring | Monitoreo en tiempo real de la protección |
| Process Hiding | Optional process hiding capabilities | *Opcional* Oculta el proceso | DESACTIVATED BY DEFAULT | DESACTIVADO POR DEFECTO

### ⚡ Technical Features | Características Técnicas

| Feature | Description | Descripción |
|---|---:|---|
| Lightweight | Minimal performance impact | Impacto mínimo en el rendimiento |
| Easy Integration | Single header and source file | Un solo archivo header y fuente |
| Cross-Platform | Windows 7/8/10/11 support | Soporte para Windows 7/8/10/11 |
| No Dependencies | Pure C++17, no external libraries | C++17 puro, sin librerías externas |

---

## 📖 Usage Examples | Ejemplos de Uso

### Basic Protection | Protección Básica

```cpp
#include "protection.h"
#include <iostream>

int main() {
    // Initialize all protections
    // Inicializar las protecciones
    LeuProtection::Initialize();

    std::cout << "Application is now protected!" << std::endl;
    std::cout << "¡La aplicación está ahora protegida!" << std::endl;
}
```

### Advanced Configuration | Configuración Avanzada

```cpp
#include "protection.h"
#include <windows.h>

int main() {
    // Initialize protections
    // Inicializar protecciones
    LeuProtection::Initialize();

    // Check if debugger is detected and close it
    // Verificar si se detecta un debugger y cerrarlo
    if (LeuProtection::IsDebuggerDetected()) {
        ExitProcess(0);
    }
}
```

---

## 🏗️ API Reference | Referencia de API

**Core Functions | Funciones Principales**

```cpp
// Initialize all protections | Inicializar todas las protecciones
void LeuProtection::Initialize();

// Check if debugger is detected | Verificar si se detecta un debugger
bool LeuProtection::IsDebuggerDetected();

// Shutdown protection system (optional) | Apagar sistema de protección (opcional)
void LeuProtection::Shutdown();
```

**Protection Components | Componentes de Protección**

- Memory Protection - VirtualProtect security  
- Anti-Debugging - Debugger detection and prevention  
- Code Obfuscation - Runtime code modification  
- PE Security - Header protection and cleaning  
- Process Security - Memory and process hiding

---

## 🔧 Installation | Instalación

**Method 1: Direct File Inclusion | Método 1: Inclusión Directa**

1. Download `LeuProtection.h` and `LeuProtection.cpp`  
2. Add them to your project  
3. Include the header in your main file  
4. Call `LeuProtection::Initialize()`

**Method 2: Git Submodule | Método 2: Submódulo Git**

```bash
git submodule add https://github.com/yourusername/leuprotect-lib.git
```

---

## 🎯 Use Cases | Casos de Uso

**Perfect for | Perfecto para:**

- Game Ch3ats & Mods - Protect your externals, exes or any other kind of executables
- Anti-Cracking - Prevent reverse engineering  
- DRM Systems - Software protection  
- Sensitive Applications - Security-critical software  

---

## ⚠️ Important Notes | Notas Importantes

**Legal Disclaimer | Aviso Legal**

This library is intended for educational and legitimate protection purposes only. Users are responsible for complying with all applicable laws and regulations.

Esta librería está destinada solo para fines educativos y de protección legítima. Los usuarios son responsables de cumplir con todas las leyes y regulaciones aplicables.

**Technical Notes | Notas Técnicas**

- ✅ Works with: Visual Studio, GCC, Clang on Windows  
- ✅ Compatible with: C++17 and above  
- ✅ Tested on: Windows 7, 8, 10, 11  
- ⚠️ Anti-cheat compatibility: May trigger some anti-cheat systems (if you know what you are doing, you will bypass this easily)

---

## 🤝 Contributing | Contribuyendo

We welcome contributions! | ¡Agradecemos las contribuciones!

1. Fork the project | Haz fork del proyecto  
2. Create your feature branch | Crea tu rama de características  
3. Commit your changes | Haz commit de tus cambios  
4. Push to the branch | Push a la rama  
5. Open a Pull Request | Abre un Pull Request

---

## 📄 License | Licencia

This project is licensed under the MIT License - All creditos to Leuan.  
Este proyecto está bajo la Licencia MIT - Todos los créditos a Leuan.

---

## 🐛 Reporting Issues | Reportar Problemas

Found a bug? Have a feature request? | ¿Encontraste un bug? ¿Tienes una solicitud de característica?

Open an issue on GitHub: https://github.com/yourusername/leuprotect-lib/issues

---

## 📞 Support | Soporte

- Discord: leuan

---

Made with ❤️ for the C++ security community  
Hecho con ❤️ para la comunidad de seguridad C++
