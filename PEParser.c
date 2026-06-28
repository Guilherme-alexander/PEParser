/*
AUTH: @Guilherme-Alexander

MIT License

Copyright (c) 2024 [Seu Nome]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>
#include <time.h>
#include <math.h>

// ESTILOS DE CORES PARA SAÍDA NO TERMINAL
// CORES DE TEXTO
#define BACK    "\x1b[30m"
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"
#define WHITE   "\x1b[37m"
// CORES DE FUNDO
#define BG_BACK    "\x1b[40m"
#define BG_RED     "\x1b[41m"
#define BG_GREEN   "\x1b[42m"
#define BG_YELLOW  "\x1b[43m"
#define BG_BLUE    "\x1b[44m"
#define BG_MAGENTA "\x1b[45m"
#define BG_CYAN    "\x1b[46m"
#define BG_WHITE   "\x1b[47m"
// ESTILOS DE TEXTO
#define BOLD      "\x1b[1m"
#define FAINT     "\x1b[2m"
#define ITALIC    "\x1b[3m"
#define UNDERLINE "\x1b[4m"
#define BLINK     "\x1b[5m"
#define REVERSE   "\x1b[7m"
// UTILITÁRIOS
#define RESET   "\x1b[0m"
#define BREAK_LINE "\n"

// ============================================
// FUNÇÃO PARA EXIBIR MENSAGENS DE ERRO DO WINDOWS
/**
 * Exibe uma mensagem de erro formatada a partir do código de erro do Windows
 * @param errorCode - Código do erro retornado por GetLastError()
 */
// ============================================
void displayErrorMessage(DWORD errorCode) {
    LPSTR messageBuffer = NULL;
    
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&messageBuffer,
        0,
        NULL);

    if (messageBuffer != NULL) {
        printf(RED BOLD "[-] ERRO: %s" RESET, messageBuffer);
        LocalFree(messageBuffer);
    }
    else {
        printf(RED BOLD "[-] ERRO: Não foi possível obter mensagem para o código %d" RESET, errorCode);
    }
}

// ============================================
// FUNÇÕES PARA IMPRESSÃO DOS CABEÇALHOS
/**
 * Exibe o cabeçalho DOS do arquivo PE
 */
// ============================================
void printDosHeader(LPVOID fileData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    
    printf(BREAK_LINE);
    printf(CYAN BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(CYAN BOLD "║                    CABEÇALHO DOS - DOS HEADER                  ║" RESET BREAK_LINE);
    printf(CYAN BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    
    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
        printf(GREEN "[✓] Magic MZ válido (0x%x)" RESET BREAK_LINE, dosHeader->e_magic);
    } else {
        printf(RED "[✗] Magic MZ inválido! (0x%x)" RESET BREAK_LINE, dosHeader->e_magic);
    }
    
    printf(BREAK_LINE);
    printf(YELLOW "  e_magic      (MZ): 0x%x" RESET BREAK_LINE, dosHeader->e_magic);
    printf("  e_cblp       (Bytes na última página): 0x%x" BREAK_LINE, dosHeader->e_cblp);
    printf("  e_cp         (Páginas no arquivo): 0x%x" BREAK_LINE, dosHeader->e_cp);
    printf("  e_crlc       (Realocações): 0x%x" BREAK_LINE, dosHeader->e_crlc);
    printf("  e_cparhdr    (Tamanho do cabeçalho em parágrafos): 0x%x" BREAK_LINE, dosHeader->e_cparhdr);
    printf("  e_minalloc   (Mínimo de memória extra): 0x%x" BREAK_LINE, dosHeader->e_minalloc);
    printf("  e_maxalloc   (Máximo de memória extra): 0x%x" BREAK_LINE, dosHeader->e_maxalloc);
    printf("  e_ss         (Segmento inicial da pilha): 0x%x" BREAK_LINE, dosHeader->e_ss);
    printf("  e_sp         (Ponteiro de pilha inicial): 0x%x" BREAK_LINE, dosHeader->e_sp);
    printf("  e_csum       (Checksum): 0x%x" BREAK_LINE, dosHeader->e_csum);
    printf("  e_ip         (IP inicial): 0x%x" BREAK_LINE, dosHeader->e_ip);
    printf("  e_cs         (Segmento CS inicial): 0x%x" BREAK_LINE, dosHeader->e_cs);
    printf("  e_lfarlc     (Offset da tabela de relocação): 0x%x" BREAK_LINE, dosHeader->e_lfarlc);
    printf("  e_ovno       (Número de overlays): 0x%x" BREAK_LINE, dosHeader->e_ovno);
    printf("  e_oemid      (ID OEM): 0x%x" BREAK_LINE, dosHeader->e_oemid);
    printf("  e_oeminfo    (Informações OEM): 0x%x" BREAK_LINE, dosHeader->e_oeminfo);
    printf(GREEN BOLD "  e_lfanew     (Offset para NT Headers): 0x%x" RESET BREAK_LINE, dosHeader->e_lfanew);
}

/**
 * Exibe os cabeçalhos NT (Signature, File Header e Optional Header)
 */
void printNTHeaders(LPVOID fileData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);
    
    // SIGNATURE HEADER
    printf(BREAK_LINE);
    printf(MAGENTA BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(MAGENTA BOLD "║                    ASSINATURA PE - SIGNATURE                   ║" RESET BREAK_LINE);
    printf(MAGENTA BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    
    if (imageNTHeaders->Signature == IMAGE_NT_SIGNATURE) {
        printf(GREEN "[✓] Assinatura PE válida (0x%x)" RESET BREAK_LINE, imageNTHeaders->Signature);
    } else {
        printf(RED "[✗] Assinatura PE inválida! (0x%x)" RESET BREAK_LINE, imageNTHeaders->Signature);
    }
    
    // FILE HEADER
    printf(BREAK_LINE);
    printf(BLUE BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(BLUE BOLD "║                CABEÇALHO DO ARQUIVO - FILE HEADER              ║" RESET BREAK_LINE);
    printf(BLUE BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    
    printf("  Machine: ");
    switch(imageNTHeaders->FileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386:
            printf(GREEN "0x%x (x86 - 32 bits)" RESET BREAK_LINE, imageNTHeaders->FileHeader.Machine);
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            printf(GREEN "0x%x (x64 - 64 bits)" RESET BREAK_LINE, imageNTHeaders->FileHeader.Machine);
            break;
        case IMAGE_FILE_MACHINE_ARM:
            printf(GREEN "0x%x (ARM)" RESET BREAK_LINE, imageNTHeaders->FileHeader.Machine);
            break;
        case IMAGE_FILE_MACHINE_ARM64:
            printf(GREEN "0x%x (ARM64)" RESET BREAK_LINE, imageNTHeaders->FileHeader.Machine);
            break;
        default:
            printf(YELLOW "0x%x (Desconhecido)" RESET BREAK_LINE, imageNTHeaders->FileHeader.Machine);
    }
    
    printf("  NumberOfSections: " CYAN "%d" RESET BREAK_LINE, imageNTHeaders->FileHeader.NumberOfSections);
    printf("  TimeDateStamp: 0x%x" BREAK_LINE, imageNTHeaders->FileHeader.TimeDateStamp);
    printf("  PointerToSymbolTable: 0x%x" BREAK_LINE, imageNTHeaders->FileHeader.PointerToSymbolTable);
    printf("  NumberOfSymbols: 0x%x" BREAK_LINE, imageNTHeaders->FileHeader.NumberOfSymbols);
    printf("  SizeOfOptionalHeader: 0x%x" BREAK_LINE, imageNTHeaders->FileHeader.SizeOfOptionalHeader);
    printf("  Characteristics: 0x%x" BREAK_LINE, imageNTHeaders->FileHeader.Characteristics);
    
    // OPTIONAL HEADER
    printf(BREAK_LINE);
    printf(CYAN BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(CYAN BOLD "║                CABEÇALHO OPCIONAL - OPTIONAL HEADER            ║" RESET BREAK_LINE);
    printf(CYAN BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    
    printf("  Magic: ");
    if (imageNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        printf(GREEN "0x%x (PE32 - 32 bits)" RESET BREAK_LINE, imageNTHeaders->OptionalHeader.Magic);
    } else if (imageNTHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        printf(GREEN "0x%x (PE32+ - 64 bits)" RESET BREAK_LINE, imageNTHeaders->OptionalHeader.Magic);
    } else {
        printf(YELLOW "0x%x (Desconhecido)" RESET BREAK_LINE, imageNTHeaders->OptionalHeader.Magic);
    }
    
    printf("  MajorLinkerVersion: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.MajorLinkerVersion);
    printf("  MinorLinkerVersion: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.MinorLinkerVersion);
    printf("  SizeOfCode: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.SizeOfCode);
    printf("  SizeOfInitializedData: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.SizeOfInitializedData);
    printf("  SizeOfUninitializedData: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.SizeOfUninitializedData);
    printf(GREEN BOLD "  ▶ AddressOfEntryPoint (OEP): 0x%x" RESET BREAK_LINE, imageNTHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("  BaseOfCode: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.BaseOfCode);
    printf(GREEN BOLD "  ▶ ImageBase: 0x%x" RESET BREAK_LINE, imageNTHeaders->OptionalHeader.ImageBase);
    printf("  SectionAlignment: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.SectionAlignment);
    printf("  FileAlignment: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.FileAlignment);
    printf("  MajorOperatingSystemVersion: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.MajorOperatingSystemVersion);
    printf("  MinorOperatingSystemVersion: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.MinorOperatingSystemVersion);
    printf("  MajorImageVersion: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.MajorImageVersion);
    printf("  MinorImageVersion: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.MinorImageVersion);
    printf("  MajorSubsystemVersion: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.MajorSubsystemVersion);
    printf("  MinorSubsystemVersion: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.MinorSubsystemVersion);
    printf("  Win32VersionValue: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.Win32VersionValue);
    printf(GREEN BOLD "  ▶ SizeOfImage: 0x%x" RESET BREAK_LINE, imageNTHeaders->OptionalHeader.SizeOfImage);
    printf("  SizeOfHeaders: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.SizeOfHeaders);
    printf("  CheckSum: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.CheckSum);
    
    printf("  Subsystem: ");
    switch(imageNTHeaders->OptionalHeader.Subsystem) {
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:
            printf(GREEN "0x%x (Windows GUI - Interface Gráfica)" RESET BREAK_LINE, imageNTHeaders->OptionalHeader.Subsystem);
            break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:
            printf(GREEN "0x%x (Windows CUI - Console)" RESET BREAK_LINE, imageNTHeaders->OptionalHeader.Subsystem);
            break;
        case IMAGE_SUBSYSTEM_NATIVE:
            printf(GREEN "0x%x (Nativo - Driver)" RESET BREAK_LINE, imageNTHeaders->OptionalHeader.Subsystem);
            break;
        default:
            printf(YELLOW "0x%x (Desconhecido)" RESET BREAK_LINE, imageNTHeaders->OptionalHeader.Subsystem);
    }
    
    printf("  DllCharacteristics: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.DllCharacteristics);
    printf("  SizeOfStackReserve: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.SizeOfStackReserve);
    printf("  SizeOfStackCommit: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.SizeOfStackCommit);
    printf("  SizeOfHeapReserve: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.SizeOfHeapReserve);
    printf("  SizeOfHeapCommit: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.SizeOfHeapCommit);
    printf("  LoaderFlags: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.LoaderFlags);
    printf("  NumberOfRvaAndSizes: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes);
}

/**
 * Exibe os diretórios de dados do arquivo PE
 */
void printDataDirectories(LPVOID fileData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);

    printf(BREAK_LINE);
    printf(YELLOW BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(YELLOW BOLD "║                DIRETÓRIOS DE DADOS - DATA DIRECTORIES          ║" RESET BREAK_LINE);
    printf(YELLOW BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    
    // Export Directory (0)
    printf(BREAK_LINE);
    printf(CYAN BOLD "  [0] EXPORT - Funções Exportadas" RESET BREAK_LINE);
    printf("      VirtualAddress: " GREEN "0x%x" RESET BREAK_LINE, 
           imageNTHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    printf("      Size: " GREEN "0x%x" RESET BREAK_LINE, 
           imageNTHeaders->OptionalHeader.DataDirectory[0].Size);
    
    // Import Directory (1)
    printf(BREAK_LINE);
    printf(CYAN BOLD "  [1] IMPORT - Bibliotecas Importadas" RESET BREAK_LINE);
    printf("      VirtualAddress: " GREEN "0x%x" RESET BREAK_LINE, 
           imageNTHeaders->OptionalHeader.DataDirectory[1].VirtualAddress);
    printf("      Size: " GREEN "0x%x" RESET BREAK_LINE, 
           imageNTHeaders->OptionalHeader.DataDirectory[1].Size);
    
    // Resource Directory (2)
    printf(BREAK_LINE);
    printf(CYAN BOLD "  [2] RESOURCE - Recursos (ícones, menus, etc)" RESET BREAK_LINE);
    printf("      VirtualAddress: " GREEN "0x%x" RESET BREAK_LINE, 
           imageNTHeaders->OptionalHeader.DataDirectory[2].VirtualAddress);
    printf("      Size: " GREEN "0x%x" RESET BREAK_LINE, 
           imageNTHeaders->OptionalHeader.DataDirectory[2].Size);
    
    // Exception Directory (3)
    printf(BREAK_LINE);
    printf(CYAN BOLD "  [3] EXCEPTION - Tratamento de Exceções" RESET BREAK_LINE);
    printf("      VirtualAddress: " GREEN "0x%x" RESET BREAK_LINE, 
           imageNTHeaders->OptionalHeader.DataDirectory[3].VirtualAddress);
    printf("      Size: " GREEN "0x%x" RESET BREAK_LINE, 
           imageNTHeaders->OptionalHeader.DataDirectory[3].Size);
    
    // Security Directory (4)
    printf(BREAK_LINE);
    printf(CYAN BOLD "  [4] SECURITY - Segurança/Assinatura Digital" RESET BREAK_LINE);
    printf("      VirtualAddress: " GREEN "0x%x" RESET BREAK_LINE, 
           imageNTHeaders->OptionalHeader.DataDirectory[4].VirtualAddress);
    printf("      Size: " GREEN "0x%x" RESET BREAK_LINE, 
           imageNTHeaders->OptionalHeader.DataDirectory[4].Size);
    
    // Debug Directory (6)
    printf(BREAK_LINE);
    printf(CYAN BOLD "  [6] DEBUG - Informações de Debug" RESET BREAK_LINE);
    printf("      VirtualAddress: " GREEN "0x%x" RESET BREAK_LINE, 
           imageNTHeaders->OptionalHeader.DataDirectory[6].VirtualAddress);
    printf("      Size: " GREEN "0x%x" RESET BREAK_LINE, 
           imageNTHeaders->OptionalHeader.DataDirectory[6].Size);
}

/**
 * Exibe os cabeçalhos das seções do arquivo PE
 */
void printSectionHeaders(LPVOID fileData) {
    printf(BREAK_LINE);
    printf(GREEN BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(GREEN BOLD "║                 CABEÇALHOS DE SEÇÃO - SECTION HEADERS          ║" RESET BREAK_LINE);
    printf(GREEN BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);
    
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)imageNTHeaders +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        imageNTHeaders->FileHeader.SizeOfOptionalHeader);
    
    printf(BREAK_LINE);
    printf(BOLD "Total de seções: %d" RESET BREAK_LINE, imageNTHeaders->FileHeader.NumberOfSections);

    for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
        printf(BREAK_LINE);
        printf(CYAN BOLD "  ─── SEÇÃO [%d] ───" RESET BREAK_LINE, i);
        
        printf(BOLD "  Nome: " GREEN "%s" RESET BREAK_LINE, sectionHeader->Name);
        
        printf("  Características: 0x%x" BREAK_LINE, sectionHeader->Characteristics);
        printf("    ");
        
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            printf(GREEN "[EXECUTÁVEL] " RESET);
        }
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ) {
            printf(GREEN "[LEITURA] " RESET);
        }
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
            printf(YELLOW "[ESCRITA] " RESET);
        }
        if (sectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
            printf(CYAN "[DESCARTÁVEL] " RESET);
        }
        if (sectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) {
            printf(CYAN "[CÓDIGO] " RESET);
        }
        if (sectionHeader->Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) {
            printf(CYAN "[DADOS INICIALIZADOS] " RESET);
        }
        if (sectionHeader->Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) {
            printf(CYAN "[DADOS NÃO INICIALIZADOS] " RESET);
        }
        printf(BREAK_LINE);
        
        printf("  VirtualSize: " GREEN "0x%x" RESET BREAK_LINE, sectionHeader->Misc.VirtualSize);
        printf("  VirtualAddress (RVA): " GREEN "0x%x" RESET BREAK_LINE, sectionHeader->VirtualAddress);
        printf("  SizeOfRawData (em disco): " GREEN "0x%x" RESET BREAK_LINE, sectionHeader->SizeOfRawData);
        printf("  PointerToRawData (offset no arquivo): " GREEN "0x%x" RESET BREAK_LINE, sectionHeader->PointerToRawData);
        printf("  PointerToRelocations: 0x%x" BREAK_LINE, sectionHeader->PointerToRelocations);
        printf("  PointerToLinenumbers: 0x%x" BREAK_LINE, sectionHeader->PointerToLinenumbers);
        printf("  NumberOfRelocations: 0x%x" BREAK_LINE, sectionHeader->NumberOfRelocations);
        printf("  NumberOfLinenumbers: 0x%x" BREAK_LINE, sectionHeader->NumberOfLinenumbers);
        
        sectionHeader++;
    }
}

/**
 * Converte RVA para RAW offset no arquivo
 */
DWORD RVAToRaw(LPVOID fileData, DWORD rva) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((DWORD_PTR)ntHeaders +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        ntHeaders->FileHeader.SizeOfOptionalHeader);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (rva >= section->VirtualAddress && 
            rva < section->VirtualAddress + section->Misc.VirtualSize) {
            return (rva - section->VirtualAddress) + section->PointerToRawData;
        }
        section++;
    }
    return 0;
}

/**
 * Analisa e exibe a tabela de importação
 */
void printImports(LPVOID fileData) {
    printf(BREAK_LINE);
    printf(CYAN BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(CYAN BOLD "║              TABELA DE IMPORTAÇÃO - IMPORT TABLE               ║" RESET BREAK_LINE);
    printf(CYAN BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);
    
    DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) {
        printf(YELLOW "  Nenhuma importação encontrada" RESET BREAK_LINE);
        return;
    }

    DWORD importRaw = RVAToRaw(fileData, importRVA);
    if (importRaw == 0) {
        printf(RED "  Erro: Não foi possível localizar a tabela de importação" RESET BREAK_LINE);
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)fileData + importRaw);
    
    int dllCount = 0;
    while (importDesc->Name != 0) {
        dllCount++;
        char* dllName = (char*)((uintptr_t)fileData + RVAToRaw(fileData, importDesc->Name));
        
        printf(BREAK_LINE);
        printf(GREEN BOLD "  ─── DLL [%d]: %s" RESET BREAK_LINE, dllCount, dllName);
        
        if (importDesc->OriginalFirstThunk != 0) {
            DWORD thunkRaw = RVAToRaw(fileData, importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA32 thunk = (PIMAGE_THUNK_DATA32)((uintptr_t)fileData + thunkRaw);
            
            int funcCount = 0;
            while (thunk->u1.AddressOfData != 0) {
                if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)) {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)
                        ((uintptr_t)fileData + RVAToRaw(fileData, (DWORD)thunk->u1.AddressOfData));
                    printf("    - %s" BREAK_LINE, importByName->Name);
                    funcCount++;
                } else {
                    printf("    - Ordinal: %d" BREAK_LINE, thunk->u1.Ordinal & 0xFFFF);
                    funcCount++;
                }
                thunk++;
            }
            printf("    Total funções: %d" BREAK_LINE, funcCount);
        }
        importDesc++;
    }
    printf(BREAK_LINE);
    printf(GREEN "  Total de DLLs importadas: %d" RESET BREAK_LINE, dllCount);
}

/**
 * Analisa e exibe a tabela de exportação
 */
void printExports(LPVOID fileData) {
    printf(BREAK_LINE);
    printf(MAGENTA BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(MAGENTA BOLD "║              TABELA DE EXPORTAÇÃO - EXPORT TABLE               ║" RESET BREAK_LINE);
    printf(MAGENTA BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);
    
    DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRVA == 0) {
        printf(YELLOW "  Nenhuma exportação encontrada" RESET BREAK_LINE);
        return;
    }

    DWORD exportRaw = RVAToRaw(fileData, exportRVA);
    if (exportRaw == 0) {
        printf(RED "  Erro: Não foi possível localizar a tabela de exportação" RESET BREAK_LINE);
        return;
    }

    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((uintptr_t)fileData + exportRaw);
    
    printf(BREAK_LINE);
    printf("  Número de funções exportadas: %d" BREAK_LINE, exportDir->NumberOfFunctions);
    printf("  Número de nomes: %d" BREAK_LINE, exportDir->NumberOfNames);
    
    DWORD* functions = (DWORD*)((uintptr_t)fileData + RVAToRaw(fileData, exportDir->AddressOfFunctions));
    DWORD* names = (DWORD*)((uintptr_t)fileData + RVAToRaw(fileData, exportDir->AddressOfNames));
    WORD* ordinals = (WORD*)((uintptr_t)fileData + RVAToRaw(fileData, exportDir->AddressOfNameOrdinals));
    
    printf(BREAK_LINE);
    printf(GREEN BOLD "  Funções exportadas:" RESET BREAK_LINE);
    for (int i = 0; i < exportDir->NumberOfNames; i++) {
        char* funcName = (char*)((uintptr_t)fileData + RVAToRaw(fileData, names[i]));
        DWORD funcRVA = functions[ordinals[i]];
        printf("    - %s (RVA: 0x%x)" BREAK_LINE, funcName, funcRVA);
    }
}

/**
 * Detecta possíveis packers/compiladores
 */
void detectCompiler(LPVOID fileData) {
    printf(BREAK_LINE);
    printf(YELLOW BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(YELLOW BOLD "║                    DETECÇÃO DE COMPILADOR                      ║" RESET BREAK_LINE);
    printf(YELLOW BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((DWORD_PTR)ntHeaders +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        ntHeaders->FileHeader.SizeOfOptionalHeader);

    int isMSVC = 0, isMinGW = 0, isUPX = 0;
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        char name[9] = {0};
        memcpy(name, section->Name, 8);
        
        if (strcmp(name, "UPX0") == 0 || strcmp(name, "UPX1") == 0) {
            isUPX = 1;
        }
        if (strstr(name, ".rdata") || strcmp(name, ".reloc") == 0) {
            isMSVC = 1;
        }
        if (strcmp(name, ".ctors") == 0 || strcmp(name, ".dtors") == 0) {
            isMinGW = 1;
        }
        section++;
    }

    printf(BREAK_LINE);
    if (isUPX) {
        printf(RED BOLD "  ⚠ POSSÍVEL PACKER DETECTADO: UPX" RESET BREAK_LINE);
        printf("  O arquivo pode estar compactado/empacotado" BREAK_LINE);
    }
    
    if (isMSVC) {
        printf(GREEN "  Compilador: Microsoft Visual C++" RESET BREAK_LINE);
    } else if (isMinGW) {
        printf(GREEN "  Compilador: MinGW/GCC" RESET BREAK_LINE);
    } else {
        printf(YELLOW "  Compilador: Desconhecido ou outros" RESET BREAK_LINE);
    }

    printf("  Versão do Linker: %d.%d" BREAK_LINE, 
           ntHeaders->OptionalHeader.MajorLinkerVersion,
           ntHeaders->OptionalHeader.MinorLinkerVersion);
}

/**
 * Calcula entropia da seção para detectar compressão/criptografia
 */
double calculateEntropy(BYTE* data, DWORD size) {
    if (size == 0) return 0.0;
    
    int freq[256] = {0};
    for (DWORD i = 0; i < size; i++) {
        freq[data[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

/**
 * Analisa entropia das seções
 */
void analyzeEntropy(LPVOID fileData) {
    printf(BREAK_LINE);
    printf(BLUE BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(BLUE BOLD "║                    ANÁLISE DE ENTROPIA                         ║" RESET BREAK_LINE);
    printf(BLUE BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((DWORD_PTR)ntHeaders +
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        ntHeaders->FileHeader.SizeOfOptionalHeader);

    printf(BREAK_LINE);
    printf("  Entropia (0 = nenhuma aleatoriedade, 8 = alta aleatoriedade)" BREAK_LINE);
    printf("  Seções com entropia > 7.5 podem indicar compressão/criptografia" BREAK_LINE);
    printf(BREAK_LINE);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (section->SizeOfRawData > 0) {
            BYTE* sectionData = (BYTE*)((uintptr_t)fileData + section->PointerToRawData);
            double entropy = calculateEntropy(sectionData, section->SizeOfRawData);
            
            char name[9] = {0};
            memcpy(name, section->Name, 8);
            
            printf("  %s: ", name);
            if (entropy > 7.5) {
                printf(RED "%.3f ⚠ ALTA" RESET, entropy);
            } else if (entropy > 6.0) {
                printf(YELLOW "%.3f ⚠ MÉDIA" RESET, entropy);
            } else {
                printf(GREEN "%.3f ✓ BAIXA" RESET, entropy);
            }
            printf(BREAK_LINE);
        }
        section++;
    }
}

// MENU
void printMenu() {
    printf(BREAK_LINE);
    printf(BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(BOLD "║                      MENU DE OPÇÕES                            ║" RESET BREAK_LINE);
    printf(BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    printf(BREAK_LINE);
    printf(BLUE "  [1] " RESET "DOS Header" BREAK_LINE);
    printf(BLUE "  [2] " RESET "NT Headers" BREAK_LINE);
    printf(BLUE "  [3] " RESET "Data Directories" BREAK_LINE);
    printf(BLUE "  [4] " RESET "Section Headers" BREAK_LINE);
    printf(GREEN "  [5] " RESET "Import Table" BREAK_LINE);
    printf(GREEN "  [6] " RESET "Export Table" BREAK_LINE);
    printf(GREEN "  [7] " RESET "Detect Compiler" BREAK_LINE);
    printf(GREEN "  [8] " RESET "Entropy Analysis" BREAK_LINE);
    printf(GREEN "  [9] " RESET "Show ALL" BREAK_LINE);
    printf(RED BOLD "  [0] " RESET "Exit" BREAK_LINE);
    printf(BREAK_LINE);
    printf(YELLOW "Digite a opção desejada: " RESET);
}

// MAIN :D
int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);

    char fileName[MAX_PATH] = {0};
    int option = -1;

    // Suporte a argumentos por linha de comando (MODO CLI)
    if (argc > 1) {
        strncpy(fileName, argv[1], MAX_PATH - 1);
        printf(CYAN "[*] Arquivo recebido por argumento: %s" RESET BREAK_LINE, fileName);
    } else {
        printf(BREAK_LINE);
        printf(GREEN BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
        printf(GREEN BOLD "║                    PE PARSER - ANALISADOR DE PE                ║" RESET BREAK_LINE);
        printf(GREEN BOLD "║                    Versão 2.0 - Windows x86/x64                ║" RESET BREAK_LINE);
        printf(GREEN BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
        printf(BREAK_LINE);
        printf(YELLOW "Digite o caminho do arquivo PE: " RESET);
        scanf("%s", fileName);
    }

    printf(CYAN "[*] Arquivo selecionado: %s" RESET BREAK_LINE, fileName);

    // ABRE O ARQUIVO
    HANDLE hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, 
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf(RED BOLD "[-] ERRO: Falha ao abrir o arquivo..." RESET BREAK_LINE);
        displayErrorMessage(GetLastError());
        return 1;
    }
    
    printf(GREEN "[✓] Arquivo aberto com sucesso!" RESET BREAK_LINE);

    // OBTÉM O TAMANHO DO ARQUIVO
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf(RED BOLD "[-] ERRO: Falha ao obter tamanho do arquivo..." RESET BREAK_LINE);
        displayErrorMessage(GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    
    printf(CYAN "[*] Tamanho do arquivo: %d bytes" RESET BREAK_LINE, fileSize);

    // ALOCA MEMÓRIA PARA O ARQUIVO
    LPVOID fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (fileData == NULL) {
        printf(RED BOLD "[-] ERRO: Falha ao alocar memória..." RESET BREAK_LINE);
        CloseHandle(hFile);
        return 1;
    }

    // LÊ O ARQUIVO PARA A MEMÓRIA
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, fileData, fileSize, &bytesRead, NULL)) {
        printf(RED BOLD "[-] ERRO: Falha ao ler o arquivo..." RESET BREAK_LINE);
        displayErrorMessage(GetLastError());
        HeapFree(GetProcessHeap(), 0, fileData);
        CloseHandle(hFile);
        return 1;
    }
    
    printf(GREEN "[✓] Arquivo lido com sucesso para memória!" RESET BREAK_LINE);

    // VALIDA SE É UM PE VÁLIDO
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf(RED BOLD "[-] ERRO: Arquivo não é um PE válido (Magic MZ não encontrado)" RESET BREAK_LINE);
        HeapFree(GetProcessHeap(), 0, fileData);
        CloseHandle(hFile);
        return 1;
    }
    
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);
    if (imageNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf(RED BOLD "[-] ERRO: Assinatura PE inválida" RESET BREAK_LINE);
        HeapFree(GetProcessHeap(), 0, fileData);
        CloseHandle(hFile);
        return 1;
    }
    
    printf(GREEN "[✓] Arquivo PE válido!" RESET BREAK_LINE);

    // LOOP MENU
    while (option != 0) {
        printMenu();
        scanf("%d", &option);
        
        switch (option) {
            case 1:
                printDosHeader(fileData);
                break;
            
            case 2:
                printNTHeaders(fileData);
                break;
            
            case 3:
                printDataDirectories(fileData);
                break;
            
            case 4:
                printSectionHeaders(fileData);
                break;
            
            case 5:
                printImports(fileData);
                break;
            
            case 6:
                printExports(fileData);
                break;
            
            case 7:
                detectCompiler(fileData);
                break;
            
            case 8:
                analyzeEntropy(fileData);
                break;
            
            case 9:
                printDosHeader(fileData);
                printNTHeaders(fileData);
                printDataDirectories(fileData);
                printSectionHeaders(fileData);
                printImports(fileData);
                printExports(fileData);
                detectCompiler(fileData);
                analyzeEntropy(fileData);
                break;
            
            case 0:
                printf(BREAK_LINE);
                printf(YELLOW BOLD "[*] Saindo do programa..." RESET BREAK_LINE);
                printf(GREEN "[✓] Até logo!" RESET BREAK_LINE);
                break;
            
            default:
                printf(RED BOLD "[-] Opção inválida! Digite um número de 0 a 9." RESET BREAK_LINE);
                break;
        }
    }
    
    // LIMPEZA DE RECURSOS
    HeapFree(GetProcessHeap(), 0, fileData);
    CloseHandle(hFile);
    
    return 0;
} //FIM!
