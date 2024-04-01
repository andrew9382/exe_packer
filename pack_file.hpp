#pragma once

#define PF_NUMBER_OF_SECTIONS			3
#define PF_SECTION_ALIGNMENT			0x1000
#define PF_FILE_ALIGNMENT				0x200
#define PF_STACK_RESERVE				0x100000
#define PF_STACK_COMMIT					0x1000
#define PF_HEAP_RESERVE					0x100000
#define PF_HEAP_COMMIT					0x1000
#define PF_STUB_MAIN_SIGNATURE_LENGTH	0x30

#define EXE_IMAGE_BASE 0x00400000

#define ALIGN(val, alignment) (((val) / (alignment) + 1) * (alignment))
#define FILE_ALIGN(val) ALIGN(val, PF_FILE_ALIGNMENT)
#define VIRTUAL_ALIGN(val) ALIGN(val, PF_SECTION_ALIGNMENT)

#define ALIGN_DW(val, alignment) ((DWORD)ALIGN(val, alignment))
#define FILE_ALIGN_DW(val) ((DWORD)FILE_ALIGN(val))
#define VIRTUAL_ALIGN_DW(val) ((DWORD)VIRTUAL_ALIGN(val))

#define ALIGN_SECTION_BY_FILE_ALIGNMENT(out_file) PushValueInVector((out_file), 0, FILE_ALIGN(out_file->size()) - out_file->size())
#define PUSH_DATA_IN_VECTOR(out_file, data) PushBytesInVector((out_file), &(data), sizeof(data))

bool PackFile(const wchar_t* file_path);

void PushBytesInVector(std::vector<BYTE>* vec, void* ptr, size_t size);

void PushValueInVector(std::vector<BYTE>* vec, int value, size_t size);

void PushBytesInVectorByAlignment(std::vector<BYTE>* vec, void* ptr, size_t size, size_t alignment);

std::vector<BYTE>* GenerateCompressedFile(std::vector<BYTE>& compressed_file, BYTE* file_raw);

void SetEntryPointAddress(std::vector<BYTE>* vec, DWORD entry_point_addr);

void GetSizeAndAddressOfSegmentInThisFile(const char* segment_name, uintptr_t* out_virtual_address, size_t* out_size);