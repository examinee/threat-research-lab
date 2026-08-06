#include <windows.h>
#include <stdio.h>
#include <intrin.h>
typedef NTSTATUS(NTAPI* pfnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,          // 프로세스 핸들 (자신: NtCurrentProcess() 또는 GetCurrentProcess())
    PVOID* BaseAddress,            // 할당받을 메모리 주소의 포인터 (입출력)
    ULONG_PTR ZeroBits,            // 0으로 설정
    PSIZE_T RegionSize,            // 할당할 메모리 크기 포인터 (입출력)
    ULONG AllocationType,          // MEM_COMMIT | MEM_RESERVE 등
    ULONG Protect                  // PAGE_EXECUTE_READWRITE 등 메모리 보호 성향
);
typedef NTSTATUS(NTAPI* pfnNtWriteVirtualMemory)(
    HANDLE ProcessHandle,          // 대상 프로세스 핸들
    PVOID BaseAddress,             // 데이터를 쓸 대상 메모리 주소
    PVOID Buffer,                  // 쓸 데이터가 담긴 버퍼 주소
    SIZE_T NumberOfBytesToWrite,   // 쓸 바이트 크기
    PSIZE_T NumberOfBytesWritten   // 실제 쓰여진 바이트 수를 반환받을 포인터 (선택 사항, NULL 가능)
);

DWORD djb2(const char* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    return hash;
}
DWORD djb2_w(const wchar_t* str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
        
    
    return hash;

}

BYTE* getmodule(DWORD target_hash){
    BYTE* peb = (BYTE*)__readgsqword(0x60); // PEB 접근
    BYTE* ldr = *(BYTE**)((BYTE*)peb + 0x18);  //ldr 접근
    BYTE* head  = (BYTE*)ldr + 0x20; //InMemoryOrderModuleList 접근
    BYTE* current = *(BYTE**)head; // InMemoryOrderModuleList의 타입인 LIst_Entry 구조체의 Flink를 통해 첫 번째 모듈의 LDR_DATA_TABLE_ENTRY 구조체 접근
    while (current != head) {
        BYTE* entry = current;  // 첫번 째 모듈의 LDR_DATA_TABLE_ENTRY 구조체의 InMemoryOrderModuleList 접근
        BYTE* dllBase = *(BYTE**)(entry + 0x20);  // 첫번 째 모듈의 LDR_DATA_TABLE_ENTRY 구조체의 DllBase멤버 접근
        wchar_t* dllName = *(wchar_t**)(entry + 0x50);  // 첫번 째 모듈의 LDR_DATA_TABLE_ENTRY 구조체의 DllName멤버 접근
        if (dllName > 0 && djb2_w(dllName) == target_hash) {
        
            return dllBase;
        }
        current = *(BYTE**)current; // 두번째 모듈의 LDR_DATA_TABLE_ENTRY 구조체의 InMemoryOrderModuleList 접근
    }
    return NULL;
}

DWORD getfuncname(BYTE* dllbase,DWORD target_hash){
    BYTE* base = dllbase;
    DWORD e_lfanew = *(DWORD*)(base + 0x3c); //e_lfanew 값을 읽어 PE 헤더 위치 계산
    BYTE* pe_header = base + e_lfanew;
    BYTE* opt_header = pe_header + 0x18; // PE 헤더에서 Optional Header 위치 계산    
    DWORD Export_Directory_RVA = *(DWORD*)(opt_header + 0x70); //pe + 0x78  ExportDirectory VA
    BYTE* IMAGE_EXPORT_DIRECTORY = base + Export_Directory_RVA;
    DWORD numberOfNames = *(DWORD*)(IMAGE_EXPORT_DIRECTORY + 0x18); // +18  NumberOfNames 함수 갯수
    DWORD AddressOfFunctions  = *(DWORD*)(IMAGE_EXPORT_DIRECTORY + 0x1C); // +1C  AddressOfFunctions 함수 주소 테이블 RVA
    DWORD AddressOfNames   = *(DWORD*)(IMAGE_EXPORT_DIRECTORY + 0x20); // +20  AddressOfNames 함수 이름 테이블 RVA
    BYTE* func_address = base + AddressOfFunctions;
    DWORD* func_name = (DWORD*)(base + AddressOfNames);
    DWORD AddressOfNameOrdinals = *(DWORD*)(IMAGE_EXPORT_DIRECTORY + 0x24); // +24  AddressOfNameOrdinals 함수 오디널 테이블 RVA
    WORD* ordinal_table = (WORD*)(base + AddressOfNameOrdinals);
    for (DWORD i = 0; i < numberOfNames; i++) {
        DWORD func_name_rva = func_name[i];
        char* func_name_str = (char*)(base + func_name_rva);
        DWORD func_str_hash = djb2(func_name_str);
        if (func_str_hash == target_hash) {
            WORD ordinal = ordinal_table[i];        // i → EAT 인덱스 변환
            DWORD* func_table = (DWORD*)(base + AddressOfFunctions);
            DWORD funcRVA = func_table[ordinal];    // 실제 함수 RVA
            BYTE* funcAddr = base + funcRVA;
            DWORD ssn = *(DWORD*)((BYTE*)funcAddr + 4); // syscall 번호는 함수 시작 4바이트 이후에 위치 
            return ssn;
        }
    }
    return 0;
}
void* get_ntdll_text_section(BYTE* dllbase){
    BYTE* base = dllbase;
    DWORD e_lfanew = *(DWORD*)(base + 0x3c); //e_lfanew 값을 읽어 PE 헤더 위치 계산
    BYTE* pe_header = base + e_lfanew;
    BYTE* opt_header = pe_header + 0x18; // PE 헤더에서 Optional Header 위치 계산
    WORD optHeaderSize = *(WORD*)(pe_header + 0x14); // PE 헤더에서 Optional Header Size 위치 계산
    WORD numSections = *(WORD*)(pe_header + 0x06); 
    BYTE* section_header_start = (opt_header + optHeaderSize); // PE 헤더에서 Section Header 시작 위치 계산
    for (int i = 0; i < numSections; i++) {
        BYTE* sections = section_header_start + (i*0x28);
        if ((*(DWORD*)(sections+0x24) & 0x20000000)) { // IMAGE_SCN_MEM_EXECUTE 플래그 확인
            DWORD section_size = *(DWORD*)(sections + 0x08); // Section Size 위치 계산
            DWORD virtualAddr = *(DWORD*)(sections + 0x0C); // Section Virtual Address 위치 계산
            BYTE* TEXT_START = base + virtualAddr; // Section Virtual Address 계산
            BYTE* TEXT_END = TEXT_START + section_size; // Section Virtual Address + Section Size 계산
            for (BYTE* p = TEXT_START; p < TEXT_END - 2; p++) {
                if (p[0] == 0x0F && p[1] == 0x05 && p[2] == 0xC3) {
                    return (void*)p;
                }
            }
        }
    }
    return NULL;

}


int main() {
    DWORD syscall_num =0;
    extern void SetSSN(DWORD ssn);
    extern void SetGadget(void* addr);
    BYTE* dll_addr = getmodule(0x22D3B5ED); // 예: ntdll.dll의 해시 값
    syscall_num = getfuncname(dll_addr, 0x6793c34c); // 예: NtAllocateVirtualMemory의 해시 값
    printf("ssn: %d\n", syscall_num);
    BYTE* syscall_gadget = get_ntdll_text_section(dll_addr); // syscall;ret 가젯 주소
    SetGadget(syscall_gadget); //init syscall gadget
    extern NTSTATUS AllocSyscall(
    HANDLE ProcessHandle,       // rcx → r10
    PVOID* BaseAddress,         // rdx
    ULONG_PTR ZeroBits,         // r8
    PSIZE_T RegionSize,         // r9
    ULONG AllocationType,       // 스택
    ULONG Protect               // 스택
    );
    extern NTSTATUS WriteSyscall(
    HANDLE ProcessHandle,          // 대상 프로세스 핸들
    PVOID BaseAddress,             // 데이터를 쓸 메모리 가상 주소
    PVOID Buffer,                  // 쓸 데이터가 담긴 버퍼 주소
    SIZE_T NumberOfBytesToWrite,   // 쓸 바이트 크기
    PSIZE_T NumberOfBytesWritten   // 실제로 쓰인 바이트 수를 받을 포인터 (선택 사항, NULL 가능)
    );
    SetSSN(syscall_num); // NtAllocateVirtualMemory
    PVOID addr = NULL;
    SIZE_T size = 0x1000;
    NTSTATUS allocstatus = AllocSyscall(
        GetCurrentProcess(),
        &addr,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    syscall_num = getfuncname(dll_addr, 0x95F3A792); // 예: NtWriteVirtualMemory 해시 값
    printf("ssn: %ld\n", syscall_num);
    SetSSN(syscall_num); // NtWriteVirtualMemory
    char dataToWrite[] = "Hello, World!";
    SIZE_T bytesWritten = 0;
    NTSTATUS writestatus = WriteSyscall(
        GetCurrentProcess(),       // 자신 프로세스에 쓰기
        addr,              // 쓰기 대상 주소
        dataToWrite,               // 원본 데이터
        sizeof(dataToWrite),       // 크기
        &bytesWritten              // 실제 쓰인 크기
    ); 
    printf("allocated memory at %p\n", addr);
    printf("writed memory at %s\n", addr);
    return 0;


}
