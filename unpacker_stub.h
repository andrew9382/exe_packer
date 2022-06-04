#pragma once

#define NT_LOCAL(func) f_##func func

#define PEB_PTR_64 (PEB*)__readgsqword(0x60)
#define PEB_PTR_32 (PEB*)__readfsdword(0x30)

#ifdef _WIN64
#define PEB_PTR PEB_PTR_64
#else
#define PEB_PTR PEB_PTR_32
#endif

#define MAX_IMPORT_NAME_SIZE 50

#define RELOC_FLAG_64(rel_info) ((rel_info >> 12) == IMAGE_REL_BASED_DIR64)
#define RELOC_FLAG_32(rel_info) ((rel_info >> 12) == IMAGE_REL_BASED_HIGHLOW)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG_64
#else
#define RELOC_FLAG RELOC_FLAG_32
#endif

using OriginalEntryPoint = void (__cdecl*)();
using f_LoadLibraryA = decltype(LoadLibraryA)*;

struct STUB_FUNCTION_TABLE
{
	NT_LOCAL(RtlAllocateHeap);
	NT_LOCAL(RtlCreateHeap);
	NT_LOCAL(RtlFreeHeap);
	NT_LOCAL(RtlZeroMemory);
	NT_LOCAL(LdrGetProcedureAddress);
	NT_LOCAL(LdrLoadDll);
	NT_LOCAL(NtAllocateVirtualMemory);
	NT_LOCAL(NtContinue);
	NT_LOCAL(NtGetContextThread);
	NT_LOCAL(NtFreeVirtualMemory);
	NT_LOCAL(memmove);

	void* p_Heap = nullptr;
};

CODE_SEG(".stub_f") BYTE* __stdcall StubMain();

template <class T>
__forceinline T* _HeapAlloc(STUB_FUNCTION_TABLE* f, size_t size)
{
	return (T*)f->RtlAllocateHeap(f->p_Heap, HEAP_ZERO_MEMORY, sizeof(T) * size);
}

__forceinline bool _FreeHeap(STUB_FUNCTION_TABLE* f, void* ptr)
{
	return (bool)f->RtlFreeHeap(f->p_Heap, NULL, ptr);
}

__forceinline int __strlen(const char* str)
{
	int i = 0;

	for (; *str; ++str, i += sizeof(char));

	return i;
}

__forceinline bool __strcmp(const char* str1, const char* str2)
{
	if (__strlen(str1) != __strlen(str2))
	{
		return false;
	}

	for (; *str1 && *str2; ++str1, ++str2)
	{
		if (*str1 != *str2)
		{
			return false;
		}
	}

	return true;
}

__forceinline int __wcslen(const wchar_t* str)
{
	int i = 0;

	for (; *str; ++str, i += sizeof(wchar_t));

	return i;
}

__forceinline bool __wcscmp(const wchar_t* str1, const wchar_t* str2)
{
	if (__wcslen(str1) != __wcslen(str2))
	{
		return false;
	}

	for (; *str1 && *str2; ++str1, ++str2)
	{
		if (*str1 != *str2)
		{
			return false;
		}
	}

	return true;
}

__forceinline void __strcat(char* dst, const char* src)
{
	for (; *dst; ++dst);

	for (; *src; ++src, ++dst)
	{
		*dst = *src;
	}

	*(++dst) = '\0';
}

__forceinline void __strcat(char* dst, char ch)
{
	for (; *dst; ++dst);

	*dst = ch;

	*(++dst) = '\0';
}

__forceinline void __strcpy(char* dst, const char* src)
{
	for (; *src != '\0'; ++src, ++dst)
	{
		*dst = *src;
	}

	*(++dst) = '\0';
}

__forceinline HANDLE GetThisModuleBaseAddress()
{
	PEB* peb = PEB_PTR;

	if (!peb)
	{
		return nullptr;
	}

	return peb->ImageBaseAddress;
}

__forceinline HANDLE GetDllBaseAddress(wchar_t* dll_name)
{
	if (!dll_name)
	{
		return nullptr;
	}

	PEB* peb = PEB_PTR;

	if (!peb)
	{
		return nullptr;
	}

	PEB_LDR_DATA* ldr_data = peb->Ldr;

	LIST_ENTRY* head = &ldr_data->InLoadOrderModuleListHead;
	LIST_ENTRY* current = ldr_data->InLoadOrderModuleListHead.Flink;

	LDR_DATA_TABLE_ENTRY* entry = nullptr;

	while (current != head)
	{
		entry = (LDR_DATA_TABLE_ENTRY*)current;

		if (__wcscmp(entry->BaseDllName.szBuffer, dll_name))
		{
			return entry->DllBase;
		}

		current = current->Flink;
	}

	return nullptr;
}


__forceinline bool InitAnsiString(ANSI_STRING* ansi_str, char* str)
{
	if (!ansi_str || !str)
	{
		return false;
	}

	if (!__strlen(str))
	{
		return false;
	}

	ansi_str->szBuffer = str;
	ansi_str->Length = __strlen(str) + 1;
	ansi_str->MaxLength = ansi_str->Length * 2;

	return true;
}

__forceinline void GetSectionAddressAndSize(const char* sec_name, DWORD64 module_base, DWORD64* out_address, DWORD* out_size)
{
	if (!out_address || !out_size)
	{
		return;
	}

	IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_base;
	IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(dos_header->e_lfanew + module_base);
	IMAGE_FILE_HEADER* file_header = &nt_header->FileHeader;

	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt_header);

	for (DWORD i = 0; i < file_header->NumberOfSections; ++i, ++section)
	{
		if (__strcmp((char*)section->Name, sec_name))
		{
			*out_address = section->VirtualAddress;
			*out_size = section->SizeOfRawData;

			break;
		}
	}
}

__forceinline bool ResolveNtDllImports(STUB_FUNCTION_TABLE* f, UINT_PTR module_base, UINT_PTR nt_base)
{
	if (!f || !module_base || !nt_base)
	{
		return false;
	}

	char import_names_sec_name[IMPORT_NAMES_SECTION_SIZE];

	IMPORT_NAMES_SECTION_INIT(import_names_sec_name);
	
	DWORD64 import_names_sec_addr = 0;
	DWORD import_names_sec_size = 0;

	GetSectionAddressAndSize(import_names_sec_name, module_base, &import_names_sec_addr, &import_names_sec_size);
	
	if (!import_names_sec_addr || !import_names_sec_size)
	{
		return false;
	}

	import_names_sec_addr += module_base;

	char import_names_encryption_key[ENTRYPTYON_KEY_SIZE];

	ENCRYPTION_KEY_INIT(import_names_encryption_key);

	DWORD stub_f_count = sizeof(STUB_FUNCTION_TABLE) / sizeof(void*) - 1;

	DWORD names_count = 0;

	for (BYTE* i = (BYTE*)import_names_sec_addr, key_i = 0; i < (BYTE*)import_names_sec_addr + import_names_sec_size; ++i, ++key_i)
	{
		if (!(*i) && !(*(i + 1)))
		{
			break;
		}

		if (key_i == ENTRYPTYON_KEY_SIZE - 1)
		{
			key_i = 0;
		}

		*i ^= import_names_encryption_key[key_i];

		if (*i == '\0')
		{
			++names_count;
		}
	}

	if (names_count != stub_f_count)
	{
		return false;
	}

	IMAGE_EXPORT_DIRECTORY* export_dir = (IMAGE_EXPORT_DIRECTORY*)(((IMAGE_NT_HEADERS*)(((IMAGE_DOS_HEADER*)nt_base)->e_lfanew + nt_base))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + nt_base);

	char import_name[MAX_IMPORT_NAME_SIZE];

	for (DWORD i = 0; i < stub_f_count; ++i)
	{
		for (DWORD j = 0; ; ++j, ++import_names_sec_addr)
		{ 
			if (*(BYTE*)import_names_sec_addr == 0)
			{
				import_name[j] = '\0';
				++import_names_sec_addr;

				break;
			}

			import_name[j] = *(BYTE*)import_names_sec_addr;
		}

		bool found_flag = false;                                                     

		for (DWORD k = 0; k < export_dir->NumberOfNames; ++k)
		{
			char* export_name = (char*)((*(DWORD*)((nt_base + export_dir->AddressOfNames) + k * sizeof(DWORD)) + nt_base));

			if (__strcmp(export_name, import_name))
			{
				WORD name_ordinal = *(((WORD*)(nt_base + export_dir->AddressOfNameOrdinals)) + k);

 				*((void**)f + i) = (void*)(*(((DWORD*)(nt_base + export_dir->AddressOfFunctions)) + name_ordinal) + nt_base);

				found_flag = true;

				break;
			}
		}

		if (!found_flag)
		{
			return false;
		}
	}

	return true;
}