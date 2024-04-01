#pragma once

#define PAGE_SIZE 0x1000

#define _LOG(format, type, ...) printf("[ "##type" ] "##format"\n", __VA_ARGS__)
#define ERRLOG(format, ...) _LOG(format, "ERROR", __VA_ARGS__)
#define SUCCLOG(format, ...) _LOG(format, "SUCCESS", __VA_ARGS__)
#define LOG(format, ...) _LOG(format, "LOG", __VA_ARGS__)

#define CODE_SEG(seg_name) __declspec(code_seg(seg_name))

#define _ZeroMemory(ptr, size) memset(ptr, 0, size)

#define GET_NT_HEADERS(base) ((IMAGE_NT_HEADERS*)(((IMAGE_DOS_HEADER*)((UINT_PTR)base))->e_lfanew + (base)))

bool VerifyFile(const wchar_t* file_path, WORD desired_machine, WORD desired_characteristics);

DWORD GetOwnModuleFullPathW(fs::path& mod_name_path);

std::vector<BYTE>::iterator* SignatureScanForVector(std::vector<BYTE>::iterator& start, size_t len, std::vector<BYTE>& signature);