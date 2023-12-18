#include "includes.h"

CODE_SEG(".stub_f") CHARS_HUFFMAN_TREE* __stdcall ReadTree_ForStub(STUB_FUNCTION_TABLE* f, BYTE** start_addr)
{
	char node_type = **start_addr;

	++(*start_addr);

	if (node_type == '1')
	{
		char ch = **start_addr;
		
		++(*start_addr);

		auto* head = _HeapAlloc<CHARS_HUFFMAN_TREE>(f, 1);
		
		head->ch = ch;

		return head;
	}

	auto* head = _HeapAlloc<CHARS_HUFFMAN_TREE>(f, 1);
	
	head->ch = '%';
	head->left = ReadTree_ForStub(f, start_addr);
	head->right = ReadTree_ForStub(f, start_addr);

	return head;
}

CODE_SEG(".stub_f") void __stdcall TraverseTree_ForStub(STUB_FUNCTION_TABLE* f, CHARS_CODES_LIST** list_head, CHARS_HUFFMAN_TREE* head, char* code)
{
	if (head->left == nullptr && head->right == nullptr)
	{
		auto* ch_codes_tail = _HeapAlloc<CHARS_CODES_LIST>(f, 1);

		ch_codes_tail->ch = head->ch;
		__strcpy(ch_codes_tail->code, code);

		if ((*list_head) == nullptr)
		{
			(*list_head) = ch_codes_tail;

			return;
		}

		auto* tmp = _HeapAlloc<CHARS_CODES_LIST>(f, 1);

		tmp->next = ch_codes_tail;
		tmp->prev = (*list_head)->prev;
		tmp->ch = (*list_head)->ch;
		__strcpy(tmp->code, (*list_head)->code);

		ch_codes_tail->prev = tmp;

		(*list_head) = ch_codes_tail;

		return;
	}

	char left_code[CHAR_CODE_LEN];
	
	f->RtlZeroMemory(left_code, CHAR_CODE_LEN);

	__strcpy(left_code, code);
	__strcat(left_code, '0');

	char right_code[CHAR_CODE_LEN];
	
	f->RtlZeroMemory(right_code, CHAR_CODE_LEN);

	__strcpy(right_code, code);
	__strcat(right_code, '1');

	TraverseTree_ForStub(f, &(*list_head), head->left, left_code);
	TraverseTree_ForStub(f, &(*list_head), head->right, right_code);
}

CODE_SEG(".stub_f") void DeleteTree_ForStub(STUB_FUNCTION_TABLE* f, CHARS_HUFFMAN_TREE* head)
{
	if (head->left == nullptr && head->right == nullptr)
	{
		_FreeHeap(f, head);

		return;
	}

	DeleteTree_ForStub(f, head->left);
	DeleteTree_ForStub(f, head->right);

	_FreeHeap(f, head);
}