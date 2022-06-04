#include "includes.h"

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

	fs::path p = "C:\\Users\\Andrew\\Desktop\\new_exe.exe";

	std::fstream f(p, std::ios::out | std::ios::binary);

	f.write((char*)compressed_file->begin()._Ptr, compressed_file->size());

	f.close();

	//debug stuff
	BYTE* f_bytes = new BYTE[compressed_file->size()];

	for (DWORD i = 0; i < compressed_file->size(); ++i)
	{
		f_bytes[i] = (*compressed_file)[i];
	}

	delete compressed_file;

	IMAGE_NT_HEADERS* nt_h = (IMAGE_NT_HEADERS*)(((IMAGE_DOS_HEADER*)f_bytes)->e_lfanew + f_bytes);

	IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt_h);

	BYTE* file_in_v_mem = (BYTE*)VirtualAlloc(NULL, nt_h->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	memcpy(file_in_v_mem, f_bytes, nt_h->OptionalHeader.SizeOfHeaders);

	for (DWORD i = 0; i < nt_h->FileHeader.NumberOfSections; ++i, ++sec)
	{
		memcpy(file_in_v_mem + sec->VirtualAddress, f_bytes + sec->PointerToRawData, sec->SizeOfRawData);
	}

	BYTE* bytesss = StubMain(file_in_v_mem);

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

	// HEADERS SETUP
	IMAGE_FILE_HEADER* orig_file_header = (IMAGE_FILE_HEADER*)(&((IMAGE_NT_HEADERS*)(((IMAGE_DOS_HEADER*)file_raw)->e_lfanew + file_raw))->FileHeader);
	IMAGE_OPTIONAL_HEADER* orig_opt_header = &((IMAGE_NT_HEADERS*)(((IMAGE_DOS_HEADER*)file_raw)->e_lfanew + file_raw))->OptionalHeader;

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
	PUSH_BYTES_IN_VECTOR(out_file, &dos_header);

	// setting up PE headers
	IMAGE_NT_HEADERS nt_header = { 0 };

	nt_header.Signature = IMAGE_NT_SIGNATURE;
	
	IMAGE_FILE_HEADER* file_header = &nt_header.FileHeader;

	file_header->Machine = orig_file_header->Machine;
	file_header->Characteristics = orig_file_header->Characteristics;
	file_header->NumberOfSections = PF_NUMBER_OF_SECTIONS;
	file_header->SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
	file_header->TimeDateStamp = time(NULL);
	
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

	char RtlAllocateHeap_name[] = "RtlAllocateHeap";
	char RtlCreateHeap_name[] = "RtlCreateHeap";
	char RtlFreeHeap_name[] = "RtlFreeHeap";
	char RtlZeroMemory_name[] = "RtlZeroMemory";
	char LdrGetProcedureAddress_name[] = "LdrGetProcedureAddress";
	char LdrLoadDll_name[] = "LdrLoadDll";
	char NtAllocateVirtualMemory_name[] = "NtAllocateVirtualMemory";
	char NtContinue_name[] = "NtContinue";
	char NtGetContextThread_name[] = "NtGetContextThread";
	char NtFreeVirtualMemory_name[] = "NtFreeVirtualMemory";
	char memmove_name[] = "memmove";

	DWORD size_of_all_names = sizeof(RtlAllocateHeap_name) + sizeof(RtlCreateHeap_name) + sizeof(RtlFreeHeap_name) + sizeof(RtlZeroMemory_name) +
							  sizeof(LdrGetProcedureAddress_name) + sizeof(LdrLoadDll_name) + sizeof(NtAllocateVirtualMemory_name) + sizeof(NtContinue_name) + sizeof(NtGetContextThread_name) +
							  sizeof(NtFreeVirtualMemory_name) + sizeof(memmove_name);

	import_names_data_seg.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
	strcpy((char*)import_names_data_seg.Name, ".data");
	import_names_data_seg.SizeOfRawData = FILE_ALIGN(size_of_all_names);
	import_names_data_seg.Misc.VirtualSize = size_of_all_names;
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
	PUSH_BYTES_IN_VECTOR(out_file, &nt_header);
	PUSH_BYTES_IN_VECTOR(out_file, &import_names_data_seg);
	PUSH_BYTES_IN_VECTOR(out_file, &text_seg);
	PUSH_BYTES_IN_VECTOR(out_file, &orig_compressed_seg);

	ALIGN_SECTION_BY_FILE_ALIGNMENT(out_file);

	// import stuff
	char import_strings_encryption_key[ENTRYPTYON_KEY_SIZE];

	ENCRYPTION_KEY_INIT(import_strings_encryption_key);

	PushBytesInVector(out_file, RtlAllocateHeap_name, sizeof(RtlAllocateHeap_name));
	PushBytesInVector(out_file, RtlCreateHeap_name, sizeof(RtlCreateHeap_name));
	PushBytesInVector(out_file, RtlFreeHeap_name, sizeof(RtlFreeHeap_name));
	PushBytesInVector(out_file, RtlZeroMemory_name, sizeof(RtlZeroMemory_name));
	PushBytesInVector(out_file, LdrGetProcedureAddress_name, sizeof(LdrGetProcedureAddress_name));
	PushBytesInVector(out_file, LdrLoadDll_name, sizeof(LdrLoadDll_name));
	PushBytesInVector(out_file, NtAllocateVirtualMemory_name, sizeof(NtAllocateVirtualMemory_name));
	PushBytesInVector(out_file, NtContinue_name, sizeof(NtContinue_name));
	PushBytesInVector(out_file, NtGetContextThread_name, sizeof(NtGetContextThread_name));
	PushBytesInVector(out_file, NtFreeVirtualMemory_name, sizeof(NtFreeVirtualMemory_name));
	PushBytesInVector(out_file, memmove_name, sizeof(memmove_name));

	for (DWORD i = out_file->size() - size_of_all_names, key_i = 0; i < out_file->size(); ++i, ++key_i)
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