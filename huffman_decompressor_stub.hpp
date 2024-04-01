#pragma once

#define CHAR_CODE_LEN 0x50
#define BYTE_SIZE_IN_BITS 8
#define KEY_MAX_LEN CHAR_CODE_LEN

struct CHARS_CODES_LIST
{
	char ch;
	char code[CHAR_CODE_LEN];

	CHARS_CODES_LIST* next = nullptr;
	CHARS_CODES_LIST* prev = nullptr;
};

struct CHARS_HUFFMAN_TREE
{
	char ch;

	CHARS_HUFFMAN_TREE* left	= nullptr;
	CHARS_HUFFMAN_TREE* right	= nullptr;
};

CODE_SEG(".stub_f") CHARS_HUFFMAN_TREE* __stdcall ReadTree_ForStub(STUB_FUNCTION_TABLE* f, BYTE** start_addr);
CODE_SEG(".stub_f") void __stdcall TraverseTree_ForStub(STUB_FUNCTION_TABLE* f, CHARS_CODES_LIST** list_head, CHARS_HUFFMAN_TREE* head, char* code);
CODE_SEG(".stub_f") void DeleteTree_ForStub(STUB_FUNCTION_TABLE* f, CHARS_HUFFMAN_TREE* head);

__forceinline CHARS_CODES_LIST* FindCharCodeInList(CHARS_CODES_LIST* list_tail, char* some_code)
{
	if (!list_tail)
	{
		return nullptr;
	}

	while (true)
	{
		if (__strcmp(list_tail->code, some_code))
		{
			return list_tail;
		}

		if (list_tail->prev)
		{
			list_tail = list_tail->prev;
		
			continue;
		}

		return nullptr;
	}
}

__forceinline char* ByteToBitsInString(STUB_FUNCTION_TABLE* f, BYTE byte)
{
	char* out_str = _HeapAlloc<char>(f, BYTE_SIZE_IN_BITS + 1);
	
	for (BYTE i = 0; i < BYTE_SIZE_IN_BITS; ++i)
	{
		if ((byte << i) & 0b10000000)
		{
			out_str[i] = '1';
		}
		else
		{
			out_str[i] = '0';
		}
	}

	out_str[BYTE_SIZE_IN_BITS] = '\0';

	return out_str;
}

__forceinline BYTE* DecompressBytes(STUB_FUNCTION_TABLE* f, CHARS_CODES_LIST* list_tail, BYTE* compressed_bytes, size_t compressed_bytes_count, SIZE_T initial_bytes_count)
{
	BYTE* out_bytes = nullptr;
	SIZE_T bytes_count = initial_bytes_count;

	if (NT_FAIL(f->NtAllocateVirtualMemory(NtCurrentProcess(), (void**)&out_bytes, NULL, &bytes_count, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
	{
		return nullptr;
	}

	if (!out_bytes)
	{
		return nullptr;
	}

	SIZE_T readed_bytes = 0;
	char key[KEY_MAX_LEN];

	f->RtlZeroMemory(key, KEY_MAX_LEN);

	for (SIZE_T i = 0; readed_bytes < initial_bytes_count; ++i)
	{
		char* bits = ByteToBitsInString(f, compressed_bytes[i]);
		
		if (!bits)
		{
			return nullptr;
		}

		for (BYTE j = 0; j < BYTE_SIZE_IN_BITS; ++j)
		{
			__strcat(key, bits[j]);

			auto* node = FindCharCodeInList(list_tail, key);

			if (node)
			{
				out_bytes[readed_bytes] = node->ch;
				f->RtlZeroMemory(key, KEY_MAX_LEN);
				++readed_bytes;
			}
		}

		_FreeHeap(f, bits);
	}

	return out_bytes;
}