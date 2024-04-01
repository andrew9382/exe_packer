#include "includes.hpp"

bool CalculateCharactersFrequency(std::priority_queue<CHAR_FREQ_PAIR*, std::vector<CHAR_FREQ_PAIR*>, CharAndFreqPairComparator>& char_and_frequency_tree, BYTE* file_raw, size_t file_size)
{
	if (!file_raw || !file_size)
	{
		return false;
	}

	std::unordered_map<char, int> char_freq;
	for (size_t i = 0; i < file_size; ++i)
	{
		if (char_freq.find(file_raw[i]) == char_freq.end())
		{
			char_freq[file_raw[i]] = 1;
		}
		else
		{
			++char_freq[file_raw[i]];
		}
	}

	for (const auto& pair : char_freq)
	{
		char_and_frequency_tree.push(new CHAR_FREQ_PAIR( pair.first, pair.second ));
	}

	return true;
}

bool CharAndFreqPairComparator::operator()(const CHAR_FREQ_PAIR* left, const CHAR_FREQ_PAIR* right)
{
	return left->frequency > right->frequency;
}

CHAR_FREQ_PAIR::CHAR_FREQ_PAIR(char ch, int frequency)
{
	this->ch = ch;
	this->frequency = frequency;
}

CHAR_FREQ_PAIR::CHAR_FREQ_PAIR()
{
}

CHAR_FREQ_PAIR* BuildHuffmanTree(std::priority_queue<CHAR_FREQ_PAIR*, std::vector<CHAR_FREQ_PAIR*>, CharAndFreqPairComparator>& char_and_frequency_tree)
{
	CHAR_FREQ_PAIR* head = nullptr;

	while (char_and_frequency_tree.size() != 1)
	{
		auto* left = char_and_frequency_tree.top();
		char_and_frequency_tree.pop();

		auto* right = char_and_frequency_tree.top();
		char_and_frequency_tree.pop();

		auto* new_node = new CHAR_FREQ_PAIR;
		
		new_node->left = left;
		new_node->right = right;
		new_node->ch = '%';
		new_node->frequency = left->frequency + right->frequency;

		head = new_node;

		char_and_frequency_tree.push(head);
	}

	return head;
}

void TraverseTree(CHAR_FREQ_PAIR* head, std::map<char, std::string>& key_char_map, std::string binary_path_to_char)
{
	if (head->left == nullptr && head->right == nullptr)
	{
		key_char_map[head->ch] = binary_path_to_char;

		return;
	}

	TraverseTree(head->left, key_char_map, binary_path_to_char + '0');
	TraverseTree(head->right, key_char_map, binary_path_to_char + '1');
}

void WriteTree(CHAR_FREQ_PAIR* head, std::vector<BYTE>& compressed_file_bytes)
{
	if (head->left == nullptr && head->right == nullptr)
	{
		compressed_file_bytes.push_back('1');
		compressed_file_bytes.push_back(head->ch);

		return;
	}

	compressed_file_bytes.push_back('0');

	WriteTree(head->left, compressed_file_bytes);
	WriteTree(head->right, compressed_file_bytes);
}

size_t WriteCompressedBytes(std::map<char, std::string>& key_char_map, std::vector<BYTE>& compressed_file_bytes, BYTE* file_raw, size_t file_size)
{
	if (!file_raw || !file_size)
	{
		return 0;
	}
	
	size_t out_compressed_bytes_count = 0;

	uint16_t bits_remain = BYTE_SIZE_IN_BITS;
	BYTE out_byte = 0;

	for (size_t i = 0; i < file_size; ++i)
	{
		BYTE in_byte = file_raw[i];

		std::string key = key_char_map[in_byte];

		for (size_t j = 0; j < key.size(); ++j)
		{
			if (key[j] == '0')
			{
				out_byte <<= 1;
			}
			else
			{
				out_byte = (out_byte << 1) | 0b1;
			}

			--bits_remain;

			if (bits_remain == 0)
			{
				compressed_file_bytes.push_back(out_byte);
				
				++out_compressed_bytes_count;

				out_byte = 0;
				bits_remain = 8;
			}
		}
	}
	
	if (bits_remain)
	{
		out_byte <<= bits_remain;

		compressed_file_bytes.push_back(out_byte);

		++out_compressed_bytes_count;
	}

	return out_compressed_bytes_count;
}

void DeleteTree(CHAR_FREQ_PAIR* head)
{
	if (head->left == nullptr && head->right == nullptr)
	{
		delete head;

		return;
	}

	DeleteTree(head->left);
	DeleteTree(head->right);
	
	delete head;
}