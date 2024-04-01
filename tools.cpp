#include "includes.hpp"

bool VerifyFile(const wchar_t* file_path, WORD desired_machine, WORD desired_characteristics)
{
	if (!file_path)
	{
		return false;
	}

	std::fstream file(file_path, std::ios::binary | std::ios::in);

	if (!file.good())
	{
		return false;
	}

	DWORD file_size = fs::file_size(file_path);

	if (!file_size || file_size < PAGE_SIZE)
	{
		file.close();

		return false;
	}

	std::shared_ptr<BYTE[]> file_raw;
	
	try
	{
		file_raw.reset(new BYTE[PAGE_SIZE]);
	}
	catch (const std::exception& ex)
	{
		std::cout << ex.what() << std::endl;
		
		file.close();

		return false;
	}

	BYTE* pfile_raw = file_raw.get();

	file.read((char*)pfile_raw, PAGE_SIZE);
	file.close();

	IMAGE_DOS_HEADER*	dos_header		= nullptr;
	IMAGE_NT_HEADERS*	nt_header		= nullptr;
	IMAGE_FILE_HEADER*	file_header		= nullptr;

	dos_header = (IMAGE_DOS_HEADER*)pfile_raw;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE || dos_header->e_lfanew > PAGE_SIZE)
	{
		return false;
	}

	nt_header = (IMAGE_NT_HEADERS*)(pfile_raw + dos_header->e_lfanew);

	if (nt_header->Signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}

	file_header = &nt_header->FileHeader;

	if (!(file_header->Machine & desired_machine) || (file_header->Characteristics & desired_characteristics) != desired_characteristics)
	{
		return false;
	}

	return true;
}

DWORD GetOwnModuleFullPathW(fs::path& mod_name_path)
{
	wchar_t mod_name_buf[MAX_PATH] = { 0 };

	HMODULE h_current_module = GetModuleHandle(NULL);

	DWORD mod_name_len = GetModuleFileNameW(h_current_module, mod_name_buf, sizeof(mod_name_buf) / sizeof(mod_name_buf[0]));

	if (!mod_name_len || GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		return 0;
	}

	mod_name_path = mod_name_buf;

	return mod_name_len;
}

std::vector<BYTE>::iterator* SignatureScanForVector(std::vector<BYTE>::iterator& start, size_t len, std::vector<BYTE>& signature)
{
	if (signature.empty())
	{
		return nullptr;
	}

	bool found = false;

	for (DWORD i = 0; i < len; ++start, ++i)
	{
		found = true;

		for (DWORD j = 0; j < signature.size(); ++j)
		{
			if (start[j] != signature[j])
			{
				found = false;

				break;
			}
		}

		if (found)
		{
			return &start;
		}
	}

	return nullptr;
}