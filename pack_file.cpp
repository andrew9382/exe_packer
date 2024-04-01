#include "includes.hpp"

void SetEntryPointAddress(std::vector<BYTE>* vec, DWORD entry_point_addr)
{
	BYTE* raw_ptr = vec->begin()._Ptr;

	IMAGE_OPTIONAL_HEADER* opt_header = &((IMAGE_NT_HEADERS*)(((IMAGE_DOS_HEADER*)raw_ptr)->e_lfanew + raw_ptr))->OptionalHeader;

	opt_header->AddressOfEntryPoint = entry_point_addr;
}

void GetSizeAndAddressOfSegmentInThisFile(const char* segment_name, DWORD64* out_virtual_address, DWORD* out_size)
{
	DWORD64 this_module_base = (DWORD64)GetModuleHandle(NULL);

	IMAGE_NT_HEADERS* this_file_nt_header = (IMAGE_NT_HEADERS*)(((IMAGE_DOS_HEADER*)this_module_base)->e_lfanew + this_module_base);

	IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(this_file_nt_header);

	for (DWORD i = 0; i < this_file_nt_header->FileHeader.NumberOfSections; ++i, ++sec)
	{
		if (!strcmp(segment_name, (char*)sec->Name))
		{
			*out_virtual_address = sec->VirtualAddress + this_module_base;
			*out_size = sec->Misc.VirtualSize;

			return;
		}
	}
}

void PushBytesInVector(std::vector<BYTE>* vec, void* ptr, DWORD size)
{
	BYTE* b_ptr = (BYTE*)ptr;
	
	for (DWORD i = 0; i < size; ++i)
	{
		vec->push_back(b_ptr[i]);
	}
}

void PushValueInVector(std::vector<BYTE>* vec, int value, DWORD size)
{
	for (DWORD i = 0; i < size; ++i)
	{
		vec->push_back(value);
	}
}

void PushBytesInVectorByAlignment(std::vector<BYTE>* vec, void* ptr, DWORD size, DWORD alignment)
{
	DWORD zero_align_count = ALIGN(size, alignment) - size;

	PushBytesInVector(vec, ptr, size);
	PushValueInVector(vec, 0, zero_align_count);
}

bool PackFile(const wchar_t* file_path)
{
#ifdef _WIN64
	WORD desired_machine = IMAGE_FILE_MACHINE_AMD64;
#else
	WORD desired_machine = IMAGE_FILE_MACHINE_I386;
#endif

	if (!VerifyFile(file_path, desired_machine, IMAGE_FILE_EXECUTABLE_IMAGE))
	{
		ERRLOG("Verification of the file failed");

		return false;
	}

	std::fstream file(file_path, std::ios::in | std::ios::binary);

	DWORD file_size = fs::file_size(file_path);

	BYTE* file_raw = new BYTE[file_size];

	file.read((char*)file_raw, file_size);
	file.close();

	std::priority_queue<CHAR_FREQ_PAIR*, std::vector<CHAR_FREQ_PAIR*>, CharAndFreqPairComparator> char_and_frequency_tree;
	if (!CalculateCharactersFrequency(char_and_frequency_tree, file_raw, file_size))
	{
		delete[] file_raw;

		return false;
	}

	if (char_and_frequency_tree.size() < 2)
	{
		delete char_and_frequency_tree.top();

		delete[] file_raw;

		return false;
	}

	auto* head = BuildHuffmanTree(char_and_frequency_tree);

	char_and_frequency_tree.pop();

	std::map<char, std::string> key_char_map;
	TraverseTree(head, key_char_map, std::string());
	
	std::vector<BYTE> compressed_file_bytes;
	WriteTree(head, compressed_file_bytes);

	DeleteTree(head);

	for (DWORD i = 0; i < sizeof(DWORD); ++i)
	{
		compressed_file_bytes.push_back(((BYTE*)&file_size)[i]);
	}

	DWORD compressed_bytes_count = WriteCompressedBytes(key_char_map, compressed_file_bytes, file_raw, file_size);

	if (!compressed_bytes_count)
	{
		delete[] file_raw;

		return false;
	}

	std::vector<BYTE>* compressed_file = GenerateCompressedFile(compressed_file_bytes, file_raw);

	delete[] file_raw;

	fs::path p = L"C:\\Users\\andre\\OneDrive\\Рабочий стол\\new_exe.exe";

	std::fstream f(p, std::ios::out | std::ios::binary);

	f.write((char*)compressed_file->begin()._Ptr, compressed_file->size());

	f.close();

	return true;
}

std::vector<BYTE>* GenerateCompressedFile(std::vector<BYTE>& compressed_file, BYTE* file_raw)
{
	std::vector<BYTE>* out_file = new std::vector<BYTE>;

	if (!out_file)
	{
		return nullptr;
	}
	
	DWORD64 stub_funcs_VA = 0;
	DWORD stub_funcs_size = 0;

	GetSizeAndAddressOfSegmentInThisFile(".stub_f", &stub_funcs_VA, &stub_funcs_size);

	if (!stub_funcs_size || !stub_funcs_VA)
	{
		return nullptr;
	}

	IMAGE_FILE_HEADER* orig_file_header = &(GET_NT_HEADERS(file_raw))->FileHeader;
	IMAGE_OPTIONAL_HEADER* orig_opt_header = &(GET_NT_HEADERS(file_raw))->OptionalHeader;

	IMAGE_DOS_HEADER dos_header = { 0 };

	dos_header.e_magic = IMAGE_DOS_SIGNATURE;
	dos_header.e_lfanew = sizeof(IMAGE_DOS_HEADER);
	dos_header.e_cblp = 0x90;
	dos_header.e_cp = 0x03;
	dos_header.e_cparhdr = 0x04;
	dos_header.e_maxalloc = 0xFFFF;
	dos_header.e_sp = 0xB8;
	dos_header.e_lfarlc = 0x40;

	// pushing dos header (without DOS stub)
	PUSH_DATA_IN_VECTOR(out_file, dos_header);

	// setting up PE headers
	IMAGE_NT_HEADERS nt_header = { 0 };

	nt_header.Signature = IMAGE_NT_SIGNATURE;
	
	IMAGE_FILE_HEADER& file_header = nt_header.FileHeader;

	file_header.Machine = orig_file_header->Machine;
	file_header.Characteristics = orig_file_header->Characteristics;
	file_header.NumberOfSections = PF_NUMBER_OF_SECTIONS;
	file_header.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	file_header.TimeDateStamp = time(NULL);
	
	IMAGE_OPTIONAL_HEADER& opt_header = nt_header.OptionalHeader;

	opt_header.Magic = IMAGE_NT_OPTIONAL_HDR_MAGIC;
	opt_header.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	opt_header.SizeOfStackReserve = PF_STACK_RESERVE;
	opt_header.SizeOfStackCommit = PF_STACK_COMMIT;
	opt_header.SizeOfHeapReserve = PF_HEAP_RESERVE;
	opt_header.SizeOfHeapCommit = PF_HEAP_COMMIT;
	opt_header.FileAlignment = PF_FILE_ALIGNMENT;
	opt_header.SectionAlignment = PF_SECTION_ALIGNMENT;
	opt_header.SizeOfUninitializedData = NULL;
	opt_header.Subsystem = orig_opt_header->Subsystem;
	opt_header.MinorSubsystemVersion = orig_opt_header->MinorSubsystemVersion;
	opt_header.MajorSubsystemVersion = orig_opt_header->MajorSubsystemVersion;
	opt_header.DllCharacteristics = orig_opt_header->DllCharacteristics;
	opt_header.MajorOperatingSystemVersion = orig_opt_header->MajorOperatingSystemVersion;
	opt_header.MinorOperatingSystemVersion = orig_opt_header->MinorOperatingSystemVersion;
	opt_header.ImageBase = EXE_IMAGE_BASE;
	opt_header.SizeOfHeaders = FILE_ALIGN(sizeof(IMAGE_SECTION_HEADER) * PF_NUMBER_OF_SECTIONS + sizeof(IMAGE_NT_HEADERS) + dos_header.e_lfanew);

	IMAGE_SECTION_HEADER import_names_data_seg = { 0 };

	IMAGE_SECTION_HEADER text_seg = { 0 };

	IMAGE_SECTION_HEADER orig_compressed_seg = { 0 };

	// setting up import segment

	const char* import_names[] = { 
		"RtlAllocateHeap",
		"RtlCreateHeap",
		"RtlFreeHeap",
		"RtlZeroMemory",
		"LdrGetProcedureAddress",
		"LdrLoadDll",
		"NtAllocateVirtualMemory",
		"NtContinue",
		"NtGetContextThread",
		"NtFreeVirtualMemory",
		"memmove",
	};

	size_t import_names_count = sizeof(import_names) / sizeof(import_names[0]);
	size_t import_names_size = 0;

	for (DWORD i = 0; i < import_names_count; ++i)
	{
		import_names_size += strlen(import_names[i]) + 1;
	}

	import_names_data_seg.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
	strcpy((char*)import_names_data_seg.Name, ".data");
	import_names_data_seg.SizeOfRawData = FILE_ALIGN(import_names_size);
	import_names_data_seg.Misc.VirtualSize = import_names_size;
	import_names_data_seg.PointerToRawData = opt_header.SizeOfHeaders;
	import_names_data_seg.VirtualAddress = VIRTUAL_ALIGN(opt_header.SizeOfHeaders);

#ifndef _WIN64
	opt_header.BaseOfData = import_names_data_seg.VirtualAddress;
#endif

	// setting up text segment
	text_seg.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;
	strcpy((char*)text_seg.Name, ".text");
	text_seg.PointerToRawData = import_names_data_seg.PointerToRawData + import_names_data_seg.SizeOfRawData;
	text_seg.VirtualAddress = import_names_data_seg.VirtualAddress + VIRTUAL_ALIGN(import_names_data_seg.SizeOfRawData);
	text_seg.SizeOfRawData = FILE_ALIGN(stub_funcs_size);
	text_seg.Misc.VirtualSize = stub_funcs_size;

	opt_header.BaseOfCode = text_seg.VirtualAddress;
	opt_header.SizeOfCode = text_seg.SizeOfRawData;

	// setting up compressed data segment
	orig_compressed_seg.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
	strcpy((char*)orig_compressed_seg.Name, ".fuck_u");
	orig_compressed_seg.PointerToRawData = text_seg.PointerToRawData + text_seg.SizeOfRawData;
	orig_compressed_seg.VirtualAddress = text_seg.VirtualAddress + VIRTUAL_ALIGN(text_seg.SizeOfRawData);
	orig_compressed_seg.SizeOfRawData = FILE_ALIGN(compressed_file.size());
	orig_compressed_seg.Misc.VirtualSize = compressed_file.size();

	opt_header.SizeOfImage = VIRTUAL_ALIGN(opt_header.SizeOfHeaders) + VIRTUAL_ALIGN(import_names_data_seg.SizeOfRawData) + VIRTUAL_ALIGN(text_seg.SizeOfRawData) + VIRTUAL_ALIGN(orig_compressed_seg.SizeOfRawData);

	// pushing PE header and align whole headers section by file alignment
	PUSH_DATA_IN_VECTOR(out_file, nt_header);
	PUSH_DATA_IN_VECTOR(out_file, import_names_data_seg);
	PUSH_DATA_IN_VECTOR(out_file, text_seg);
	PUSH_DATA_IN_VECTOR(out_file, orig_compressed_seg);

	ALIGN_SECTION_BY_FILE_ALIGNMENT(out_file);

	// import stuff
	for (DWORD i = 0; i < import_names_count; ++i)
	{
		PushBytesInVector(out_file, (void*)import_names[i], strlen(import_names[i]) + 1);
	}

	char import_strings_encryption_key[ENTRYPTYON_KEY_SIZE];

	ENCRYPTION_KEY_INIT(import_strings_encryption_key);

	for (size_t i = out_file->size() - import_names_size, key_i = 0; i < out_file->size(); ++i, ++key_i)
	{
		if (key_i == ENTRYPTYON_KEY_SIZE - 1)
		{
			key_i = 0;
		}

		out_file->at(i) ^= import_strings_encryption_key[key_i];
	}

	ALIGN_SECTION_BY_FILE_ALIGNMENT(out_file);

	std::vector<BYTE> stub_main_signature;

	for (DWORD i = 0; i < PF_STUB_MAIN_SIGNATURE_LENGTH; ++i)
	{
		stub_main_signature.push_back(((BYTE*)StubMain)[i]);
	}

	PushBytesInVector(out_file, (void*)stub_funcs_VA, stub_funcs_size);
	
	std::vector<BYTE>::iterator start_of_code = out_file->end() - stub_funcs_size;

	std::vector<BYTE>::iterator* stub_main_in_file = SignatureScanForVector(start_of_code, stub_funcs_size, stub_main_signature);

	if (!stub_main_in_file)
	{
		return nullptr;
	}

	for (DWORD i = out_file->size() - stub_funcs_size, j = 0; i < out_file->size(); ++i, ++j)
	{
		if (out_file->begin() + i == *stub_main_in_file)
		{
			SetEntryPointAddress(out_file, text_seg.VirtualAddress + j);

			break;
		}
	}
	
	ALIGN_SECTION_BY_FILE_ALIGNMENT(out_file);

	for (const auto& byte : compressed_file)
	{
		out_file->push_back(byte);
	}

	ALIGN_SECTION_BY_FILE_ALIGNMENT(out_file);

	return out_file;
}