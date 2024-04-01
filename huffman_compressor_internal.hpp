#pragma once

struct CHAR_FREQ_PAIR
{
	char	ch;
	int		frequency;

	CHAR_FREQ_PAIR* left	= nullptr;
	CHAR_FREQ_PAIR* right	= nullptr;

	CHAR_FREQ_PAIR(char ch, int frequency);
	CHAR_FREQ_PAIR();
};

struct CharAndFreqPairComparator
{
	bool operator() (const CHAR_FREQ_PAIR* left, const CHAR_FREQ_PAIR* right);
};

bool CalculateCharactersFrequency(std::priority_queue<CHAR_FREQ_PAIR*, std::vector<CHAR_FREQ_PAIR*>, CharAndFreqPairComparator>& char_and_frequency_tree, BYTE* file_raw, size_t file_size);

CHAR_FREQ_PAIR* BuildHuffmanTree(std::priority_queue<CHAR_FREQ_PAIR*, std::vector<CHAR_FREQ_PAIR*>, CharAndFreqPairComparator>& char_and_frequency_tree);

void TraverseTree(CHAR_FREQ_PAIR* head, std::map<char, std::string>& key_char_map, std::string binary_path_to_char);

void WriteTree(CHAR_FREQ_PAIR* head, std::vector<BYTE>& compressed_file_bytes);

size_t WriteCompressedBytes(std::map<char, std::string>& key_char_map, std::vector<BYTE>& compressed_file_bytes, BYTE* file_raw, size_t file_size);

void DeleteTree(CHAR_FREQ_PAIR* head);