#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <Windows.h>

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

void displayErrorMessage(DWORD errorCode) {
    LPSTR messageBuffer = NULL;
    
    // Tenta obter a mensagem de erro do sistema
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

void printDosHeader(LPVOID fileData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    
    printf(BREAK_LINE);
    printf(CYAN BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(CYAN BOLD "║                    CABEÇALHO DOS - DOS HEADER                  ║" RESET BREAK_LINE);
    printf(CYAN BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    
    // Validação do magic number MZ
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
 * Esta é a parte mais importante do PE, contendo informações críticas
 * como ponto de entrada, imagem base, etc.
 */
void printNTHeaders(LPVOID fileData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);
    
    printf(BREAK_LINE);
    printf(MAGENTA BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(MAGENTA BOLD "║                    ASSINATURA PE - SIGNATURE                   ║" RESET BREAK_LINE);
    printf(MAGENTA BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    
    if (imageNTHeaders->Signature == IMAGE_NT_SIGNATURE) {
        printf(GREEN "[✓] Assinatura PE válida (0x%x)" RESET BREAK_LINE, imageNTHeaders->Signature);
    } else {
        printf(RED "[✗] Assinatura PE inválida! (0x%x)" RESET BREAK_LINE, imageNTHeaders->Signature);
    }
    
    printf(BREAK_LINE);
    printf(BLUE BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(BLUE BOLD "║                CABEÇALHO DO ARQUIVO - FILE HEADER              ║" RESET BREAK_LINE);
    printf(BLUE BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    
    // Exibe a arquitetura de forma legível
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
    
    printf(BREAK_LINE);
    printf(CYAN BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(CYAN BOLD "║                CABEÇALHO OPCIONAL - OPTIONAL HEADER            ║" RESET BREAK_LINE);
    printf(CYAN BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    
    // Magic do optional header (PE32 ou PE32+)
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
    
    // Ponto de entrada - destaque especial
    printf(GREEN BOLD "  ▶ AddressOfEntryPoint (OEP): 0x%x" RESET BREAK_LINE, imageNTHeaders->OptionalHeader.AddressOfEntryPoint);
    
    printf("  BaseOfCode: 0x%x" BREAK_LINE, imageNTHeaders->OptionalHeader.BaseOfCode);
    
    // Image Base - destaque especial
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
    
    // Subsystem - exibe de forma legível
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
 * Os diretórios mais importantes são Export e Import
 * que contêm informações sobre funções exportadas e importadas
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
 * Cada seção representa uma parte do executável (.text, .data, .rdata, etc.)
 * com suas respectivas permissões e localizações
 */
void printSectionHeaders(LPVOID fileData) {
    printf(BREAK_LINE);
    printf(GREEN BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(GREEN BOLD "║                 CABEÇALHOS DE SEÇÃO - SECTION HEADERS          ║" RESET BREAK_LINE);
    printf(GREEN BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)fileData + dosHeader->e_lfanew);
    
    // Calcula o início da tabela de seções
    PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)imageNTHeaders +
        sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER) +
        imageNTHeaders->FileHeader.SizeOfOptionalHeader);
    
    printf(BREAK_LINE);
    printf(BOLD "Total de seções: %d" RESET BREAK_LINE, imageNTHeaders->FileHeader.NumberOfSections);

    // Itera por todas as seções
    for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
        printf(BREAK_LINE);
        printf(CYAN BOLD "  ─── SEÇÃO [%d] ───" RESET BREAK_LINE, i);
        
        // Nome da seção (8 bytes, normalmente terminado em null)
        printf(BOLD "  Nome: " GREEN "%s" RESET BREAK_LINE, sectionHeader->Name);
        
        // Características da seção - exibe de forma legível
        printf("  Características: 0x%x" BREAK_LINE, sectionHeader->Characteristics);
        printf("    ");
        
        // Verifica permissões da seção
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
        
        // Move para o próximo cabeçalho de seção
        sectionHeader++;
    }
}

/**
 * Exibe o menu de opções para o usuário
 */
void printMenu() {
    printf(BREAK_LINE);
    printf(BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(BOLD "║                        MENU DE OPÇÕES                          ║" RESET BREAK_LINE);
    printf(BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    printf(BREAK_LINE);
    printf(BLUE "  [1] " RESET "DOS Header - Cabeçalho DOS" BREAK_LINE);
    printf(BLUE "  [2] " RESET "NT Headers - Cabeçalhos NT (Signature, File, Optional)" BREAK_LINE);
    printf(BLUE "  [3] " RESET "Data Directories - Diretórios de Dados (Export/Import)" BREAK_LINE);
    printf(BLUE "  [4] " RESET "Section Headers - Cabeçalhos das Seções" BREAK_LINE);
    printf(RED BOLD "  [5] " RESET "Exit - Sair do Programa" BREAK_LINE);
    printf(BREAK_LINE);
    printf(YELLOW "Digite a opção desejada: " RESET);
}

/**
 * Função principal - Ponto de entrada do programa
 */
int main(int argc, char* argv[]) {

    // Adicionar Terminal UTF-8
    SetConsoleOutputCP(CP_UTF8);

    char fileName[MAX_PATH];
    int option = -1;

    printf(BREAK_LINE);
    printf(GREEN BOLD "╔════════════════════════════════════════════════════════════════╗" RESET BREAK_LINE);
    printf(GREEN BOLD "║                    PE PARSER - ANALISADOR DE PE                ║" RESET BREAK_LINE);
    printf(GREEN BOLD "║                    Versão 1.0 - Windows x86/x64                ║" RESET BREAK_LINE);
    printf(GREEN BOLD "╚════════════════════════════════════════════════════════════════╝" RESET BREAK_LINE);
    printf(BREAK_LINE);
    
    printf(YELLOW "Digite o caminho do arquivo PE: " RESET);
    scanf("%s", fileName);
    
    printf(CYAN "[*] Arquivo selecionado: %s" RESET BREAK_LINE, fileName);
    
    HANDLE hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, 
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf(RED BOLD "[-] ERRO: Falha ao abrir o arquivo..." RESET BREAK_LINE);
        displayErrorMessage(GetLastError());
        return 1;
    }
    
    printf(GREEN "[✓] Arquivo aberto com sucesso!" RESET BREAK_LINE);
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf(RED BOLD "[-] ERRO: Falha ao obter tamanho do arquivo..." RESET BREAK_LINE);
        displayErrorMessage(GetLastError());
        CloseHandle(hFile);
        return 1;
    }
    
    printf(CYAN "[*] Tamanho do arquivo: %d bytes" RESET BREAK_LINE, fileSize);
    
    LPVOID fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (fileData == NULL) {
        printf(RED BOLD "[-] ERRO: Falha ao alocar memória..." RESET BREAK_LINE);
        CloseHandle(hFile);
        return 1;
    }
    
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, fileData, fileSize, &bytesRead, NULL)) {
        printf(RED BOLD "[-] ERRO: Falha ao ler o arquivo..." RESET BREAK_LINE);
        displayErrorMessage(GetLastError());
        HeapFree(GetProcessHeap(), 0, fileData);
        CloseHandle(hFile);
        return 1;
    }
    
    printf(GREEN "[✓] Arquivo lido com sucesso para memória!" RESET BREAK_LINE);
    
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
    
    while (option != 5) {
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
                printf(BREAK_LINE);
                printf(YELLOW BOLD "[*] Saindo do programa..." RESET BREAK_LINE);
                printf(GREEN "[✓] Até logo!" RESET BREAK_LINE);
                break;
            
            default:
                printf(RED BOLD "[-] Opção inválida! Digite um número de 1 a 5." RESET BREAK_LINE);
                break;
        }
    }
    
    HeapFree(GetProcessHeap(), 0, fileData);
    CloseHandle(hFile);
    
    return 0;
}
