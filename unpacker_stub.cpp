#include "includes.hpp"

CODE_SEG(".stub_f") int __stdcall StubMain()
{
	UINT_PTR module_base = (UINT_PTR)GetThisModuleBaseAddress();

	STUB_FUNCTION_TABLE f;

	wchar_t nt_dll[NT_DLL_NAME_SIZE];
	wchar_t kernel_32_dll[KERNEL_DLL_NAME_SIZE];

	NT_DLL_NAME_INIT_UNICODE(nt_dll);
	KERNEL_DLL_NAME_INIT_UNICODE(kernel_32_dll);

	HANDLE nt_dll_base = GetDllBaseAddress(nt_dll);
	HANDLE kernel_dll_base = GetDllBaseAddress(kernel_32_dll);
	
	if (!nt_dll_base || !kernel_dll_base)
	{
		return 0;
	}

	if (!ResolveNtDllImports(&f, module_base, (DWORD64)nt_dll_base))
	{
		return 0;
	}

	f_LoadLibraryA _LoadLibraryA = nullptr;

	ANSI_STRING LoadLibrary_ansi_name;

	char LoadLibrary_name[LOAD_LIBRARY_STR_SIZE];
	LOAD_LIBRARY_STR_INIT(LoadLibrary_name);

	if (!InitAnsiString(&LoadLibrary_ansi_name, LoadLibrary_name))
	{
		return 0;
	}

	if (NT_FAIL(f.LdrGetProcedureAddress(kernel_dll_base, &LoadLibrary_ansi_name, NULL, (void**)&_LoadLibraryA)))
	{
		return 0;
	}

	if (!_LoadLibraryA)
	{
		return 0;
	}

	f.p_Heap = f.RtlCreateHeap(HEAP_GROWABLE, NULL, NULL, NULL, NULL, NULL);

	DWORD64 compressed_section_addr = 0;
	DWORD compressed_section_size = 0;

	char compressed_section_name[COMPRESSED_SECTION_NAME_SIZE];

	COMPRESSED_SECTION_NAME_INIT(compressed_section_name);

	GetSectionAddressAndSize(compressed_section_name, module_base, &compressed_section_addr, &compressed_section_size);

	if (!compressed_section_addr || !compressed_section_size)
	{
		return 0;
	}

	compressed_section_addr += module_base;

	CHARS_HUFFMAN_TREE* tree_head = ReadTree_ForStub(&f, (BYTE**)&compressed_section_addr);

	DWORD initial_bytes_num = *(DWORD*)compressed_section_addr;
	compressed_section_addr += sizeof(DWORD);

	CHARS_CODES_LIST* list_tail = nullptr;

	char useless_var[1]; useless_var[0] = '\0';

	TraverseTree_ForStub(&f, &list_tail, tree_head, useless_var);

	DeleteTree_ForStub(&f, tree_head);
	
	BYTE* decompressed_section = DecompressBytes(&f, list_tail, (BYTE*)compressed_section_addr, compressed_section_size, initial_bytes_num);

	if (!decompressed_section)
	{
		return 0;
	}

	IMAGE_NT_HEADERS* nt_header = GET_NT_HEADERS(decompressed_section);
	IMAGE_OPTIONAL_HEADER* opt_header = &nt_header->OptionalHeader;

	BYTE* main_image_base = (BYTE*)opt_header->ImageBase;
	SIZE_T new_main_image_size = opt_header->SizeOfImage;

	SIZE_T virtual_free_size = 0;

	if (NT_FAIL(f.NtAllocateVirtualMemory(NtCurrentProcess(), (void**)&main_image_base, NULL, &new_main_image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		main_image_base = nullptr;

		if (NT_FAIL(f.NtAllocateVirtualMemory(NtCurrentProcess(), (void**)&main_image_base, NULL, &new_main_image_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
		{
			return 0;
		}
	}

	IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt_header);

	f.memmove(main_image_base, decompressed_section, opt_header->SizeOfHeaders);

	for (DWORD i = 0; i < nt_header->FileHeader.NumberOfSections; ++i, ++sec)
	{
		if (sec->SizeOfRawData)
		{
			f.memmove(main_image_base + sec->VirtualAddress, decompressed_section + sec->PointerToRawData, sec->SizeOfRawData);
		}
	}
	
	BYTE* location_delta = main_image_base - opt_header->ImageBase;

	if (location_delta)
	{
		if (!opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			return 0;
		}

		IMAGE_BASE_RELOCATION* reloc_data = (IMAGE_BASE_RELOCATION*)(main_image_base + opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (reloc_data->VirtualAddress)
		{
			DWORD amount_of_entries = (reloc_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* relative_info = (WORD*)(reloc_data + 1);

			for (DWORD i = 0; i < amount_of_entries; ++i, ++relative_info)
			{
				if (RELOC_FLAG(*relative_info))
				{
					DWORD* patch = (DWORD*)(main_image_base + reloc_data->VirtualAddress + ((*relative_info) & 0xFFF));
					*patch += (DWORD64)location_delta;
				}
			}

			reloc_data = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc_data + reloc_data->SizeOfBlock);
		}

		opt_header->ImageBase += (DWORD64)location_delta;
	}

	if (opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		IMAGE_IMPORT_DESCRIPTOR* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)(main_image_base + opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	
		while (import_desc->Name)
		{
			char* dll_name = (char*)(main_image_base + import_desc->Name);
			HMODULE h_dll = _LoadLibraryA(dll_name);

			if (!h_dll)
			{
				return 0;
			}

			IMAGE_THUNK_DATA* orig_thunk = (IMAGE_THUNK_DATA*)(main_image_base + import_desc->OriginalFirstThunk);
			IMAGE_THUNK_DATA* first_thunk = (IMAGE_THUNK_DATA*)(main_image_base + import_desc->FirstThunk);

			for (; orig_thunk->u1.AddressOfData; ++orig_thunk, ++first_thunk)
			{
				if (IMAGE_SNAP_BY_ORDINAL(orig_thunk->u1.Ordinal))
				{
					NTSTATUS st = f.LdrGetProcedureAddress(h_dll, NULL, IMAGE_ORDINAL(orig_thunk->u1.Ordinal), (void**)first_thunk);
					if (NT_FAIL(st))
					{
						return 0;
					}
				}
				else
				{
					IMAGE_IMPORT_BY_NAME* name_imp = (IMAGE_IMPORT_BY_NAME*)(main_image_base + orig_thunk->u1.AddressOfData);

					ANSI_STRING* ansi_name = _HeapAlloc<ANSI_STRING>(&f, 1);

					if (!ansi_name)
					{
						return 0;
					}

					if (!InitAnsiString(ansi_name, name_imp->Name))
					{
						return 0;
					}

					if (NT_FAIL(f.LdrGetProcedureAddress(h_dll, ansi_name, NULL, (void**)first_thunk)))
					{
						return 0;
					}

					_FreeHeap(&f, ansi_name);
				}
			}

			++import_desc;
		}
	}
	else
	{
		return 0;
	}

	UINT_PTR orig_entry_point = opt_header->AddressOfEntryPoint + (UINT_PTR)main_image_base;

	if (NT_FAIL(f.NtFreeVirtualMemory(NtCurrentProcess(), (void**)&decompressed_section, &virtual_free_size, MEM_RELEASE)))
	{
		return 0;
	}

	OriginalEntryPoint EntryPoint = (OriginalEntryPoint)orig_entry_point;

	EntryPoint();

	return 1;
}