# 🔍 PEParser - Windows Portable Executable Analyzer

[![Version](https://img.shields.io/badge/version-2.0-blue.svg)](https://github.com/yourusername/PEParser)
[![Windows](https://img.shields.io/badge/platform-Windows-0078D6.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![C](https://img.shields.io/badge/language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

> **Uma ferramenta completa para análise de arquivos PE (Portable Executable) no Windows**

<br/>

## 🎯 Sobre o Projeto

O **PEParser** é uma ferramenta de linha de comando desenvolvida em C para analisar e extrair informações detalhadas de arquivos executáveis no formato PE (Portable Executable) - o formato padrão para executáveis, bibliotecas e drivers no Windows.

Ideal para:
- 🔐 **Análise de Malware** - Identifique comportamentos suspeitos
- 🔧 **Engenharia Reversa** - Entenda a estrutura interna de executáveis
- 🛠️ **Desenvolvimento** - Depure problemas de compilação e linking
- 🎓 **Educação** - Aprenda sobre o formato PE na prática
- 🔍 **Forensics** - Extraia metadados de arquivos suspeitos

<br/>

## ✨ Funcionalidades

### 🏗️ Análise Estrutural
- ✅ **DOS Header** - Cabeçalho MS-DOS (Magic "MZ")
- ✅ **NT Headers** - Assinatura PE, File Header e Optional Header
- ✅ **Section Headers** - Todas as seções (.text, .data, .rdata, etc.)
- ✅ **Data Directories** - Export, Import, Resource, Debug, etc.

<br/>

### 🔍 Análise Avançada
- 🆕 **Tabela de Importações** - DLLs e funções importadas
- 🆕 **Tabela de Exportações** - Funções exportadas (especialmente para DLLs)
- 🆕 **Detecção de Compilador** - Identifica MSVC, MinGW/GCC, etc.
- 🆕 **Detecção de Packers** - Identifica UPX e outros packers
- 🆕 **Análise de Entropia** - Detecta seções compactadas/criptografadas

<br/>

### 🎨 Interface Visual
- 📊 **Saída Colorida** - Cores para melhor visualização
- 📐 **Formatação Estruturada** - Tabelas e bordas para organização
- 📝 **Suporte UTF-8** - Caracteres especiais e acentos
- 🖥️ **Modo Interativo** - Menu com opções numeradas

<br/>

## 📸 Capturas de Tela

### Menu Principal
```
╔════════════════════════════════════════════════════════════════╗
║                    PE PARSER - ANALISADOR DE PE                ║
║                    Versão 2.0 - Windows x86/x64                ║
╚════════════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════════════╗
║                      MENU DE OPÇÕES                            ║
╚════════════════════════════════════════════════════════════════╝

  [1] DOS Header
  [2] NT Headers
  [3] Data Directories
  [4] Section Headers
  [5] Import Table
  [6] Export Table
  [7] Detect Compiler
  [8] Entropy Analysis
  [9] Show ALL
  [0] Exit
```

### Exemplo de Análise de Entropia
```
╔════════════════════════════════════════════════════════════════╗
║                    ANÁLISE DE ENTROPIA                         ║
╚════════════════════════════════════════════════════════════════╝

  Entropia (0 = nenhuma aleatoriedade, 8 = alta aleatoriedade)
  Seções com entropia > 7.5 podem indicar compressão/criptografia

  .text: 6.234 ⚠ MÉDIA
  .data: 4.891 ✓ BAIXA
  .rsrc: 7.892 ⚠ ALTA
```

<br/>

## 📋 Requisitos

- **Sistema:** Windows XP ou superior (x86/x64)
- **Compilador:** GCC, MinGW ou Visual Studio
- **Bibliotecas:** Windows SDK (já incluída no Visual Studio)

<br/>

## 🛠️ Instalação

```bash
git clone https://github.com/Guilherme-alexander/PEParser.git

cd PEParser
```

### Compilação com GCC/MinGW

```bash
# Compilar o programa
gcc PEParser.c -o PEParser.exe -luser32 -lm

# Compilar com otimizações
gcc PEParser.c -o PEParser.exe -luser32 -lm -O2

# Compilar com debug
gcc PEParser.c -o PEParser.exe -luser32 -lm -g
```

### Compilação com Visual Studio

```cmd
cl PEParser.c /Fe:PEParser.exe /link user32.lib
```

<br/>

### Compilação com CMake (opcional)

```cmake
cmake_minimum_required(VERSION 3.10)
project(PEParser)

set(CMAKE_C_STANDARD 99)
add_executable(PEParser PEParser.c)
target_link_libraries(PEParser user32)
```

<br/>

## 🚀 Como Usar

### Uso Interativo

```bash
# Executar o programa com caminho do arquivo
PEParser.exe C:\Windows\System32\notepad.exe

# Executar o programa
PEParser.exe

# Digite o caminho do arquivo
Digite o caminho do arquivo PE: C:\Windows\System32\notepad.exe

# Escolha uma opção do menu
Digite a opção desejada: 4
```

### Uso com Argumentos

```bash
# Passar o arquivo diretamente
PEParser.exe C:\Windows\System32\notepad.exe
```

### Opções do Menu

| Opção | Descrição |
|-------|-----------|
| 1 | DOS Header - Cabeçalho MS-DOS |
| 2 | NT Headers - Assinatura PE, File e Optional Header |
| 3 | Data Directories - Export, Import, Resource, etc. |
| 4 | Section Headers - Informações de cada seção |
| 5 | Import Table - DLLs e funções importadas |
| 6 | Export Table - Funções exportadas |
| 7 | Detect Compiler - Identifica compilador/packer |
| 8 | Entropy Analysis - Análise de aleatoriedade |
| 9 | Show ALL - Exibe todas as informações |
| 0 | Exit - Sai do programa |

<br/>

## 📁 Estrutura do Código

```
PEParser/
├── PEParser.c          # Código fonte principal
├── README.md           # Documentação
├── LICENSE             # Licença MIT
├── .gitignore          # Arquivos ignorados pelo Git
└── examples/           # Exemplos de arquivos PE
    ├── hello.exe
    ├── sample.dll
    └── malware.exe (para análise)
```

### Principais Funções

```c
// Cabeçalhos básicos
void printDosHeader(LPVOID fileData);
void printNTHeaders(LPVOID fileData);
void printDataDirectories(LPVOID fileData);
void printSectionHeaders(LPVOID fileData);

// Análise avançada
void printImports(LPVOID fileData);
void printExports(LPVOID fileData);
void detectCompiler(LPVOID fileData);
void analyzeEntropy(LPVOID fileData);

// Utilitários
DWORD RVAToRaw(LPVOID fileData, DWORD rva);
double calculateEntropy(BYTE* data, DWORD size);
```

<br/>

## 📊 Exemplo de Saída

### DOS Header
```
╔════════════════════════════════════════════════════════════════╗
║                    CABEÇALHO DOS - DOS HEADER                  ║
╚════════════════════════════════════════════════════════════════╝
[✓] Magic MZ válido (0x5a4d)

  e_magic      (MZ): 0x5a4d
  e_cblp       (Bytes na última página): 0x90
  e_cp         (Páginas no arquivo): 0x3
  e_crlc       (Realocações): 0x0
  e_cparhdr    (Tamanho do cabeçalho em parágrafos): 0x4
  e_minalloc   (Mínimo de memória extra): 0x0
  e_maxalloc   (Máximo de memória extra): 0xffff
  e_ss         (Segmento inicial da pilha): 0x0
  e_sp         (Ponteiro de pilha inicial): 0xb8
  e_csum       (Checksum): 0x0
  e_ip         (IP inicial): 0x0
  e_cs         (Segmento CS inicial): 0x0
  e_lfarlc     (Offset da tabela de relocação): 0x40
  e_ovno       (Número de overlays): 0x0
  e_oemid      (ID OEM): 0x0
  e_oeminfo    (Informações OEM): 0x0
  e_lfanew     (Offset para NT Headers): 0xe0
```

### Import Table
```
╔════════════════════════════════════════════════════════════════╗
║              TABELA DE IMPORTAÇÃO - IMPORT TABLE               ║
╚════════════════════════════════════════════════════════════════╝

  ─── DLL [1]: KERNEL32.dll
    - CreateFileA
    - ReadFile
    - WriteFile
    - CloseHandle
    - GetLastError
    Total funções: 5

  ─── DLL [2]: USER32.dll
    - MessageBoxA
    - MessageBoxW
    Total funções: 2

  Total de DLLs importadas: 2
```

<br/>

## 🗺️ Roadmap

### Versão 2.0 (Atual)
- [x] Análise completa de cabeçalhos
- [x] Tabela de importações
- [x] Tabela de exportações
- [x] Detecção de compilador
- [x] Análise de entropia
- [x] Suporte a UTF-8
- [x] Cores no terminal

### Versão 2.1 (Planejado)
- [ ] Suporte a arquivos .DLL
- [ ] Exportação para JSON/XML
- [ ] Análise de recursos (ícones, menus)
- [ ] Detecção de mais packers (UPX, ASPack, etc.)
- [ ] Integração com YARA rules

### Versão 3.0 (Futuro)
- [ ] Interface gráfica (GUI)
- [ ] Análise de comportamento em sandbox
- [ ] Detecção de anti-debug
- [ ] Plugins para extensão
- [ ] Modo batch para análise de múltiplos arquivos

### Diretrizes de Contribuição

- 📝 Mantenha o código limpo e bem comentado
- 🧪 Teste suas mudanças
- 📚 Atualize a documentação
- 🎨 Siga o estilo de código existente

<br/>

## 👨‍💻 Autor

**Seu Nome**
- GitHub: [@Guilherme-alexander](https://github.com/Guilherme-alexander)
- LinkedIn: [Guilherme Alexander](https://www.linkedin.com/in/guilherme-alexander-dev/)

<br/>

## 📄 Licença

Este projeto está licenciado sob a **MIT License** - veja o arquivo [LICENSE](LICENSE) para detalhes.

<br/>

## ⭐ Mostre seu apoio

Se este projeto foi útil para você, considere:
- ⭐ Dar uma estrela no GitHub
- 🐛 Reportar bugs
- 💡 Sugerir melhorias
- 🔀 Contribuir com código

---

**Feito com ❤️ para a comunidade de segurança e desenvolvimento Windows**
[⬆ Voltar ao topo](#-peparser---windows-portable-executable-analyzer)
