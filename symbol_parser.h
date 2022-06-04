#pragma once

class SymbolParser
{
private:

	HANDLE		h_proc			= 0;
	HANDLE		nt_handle		= 0;
	DWORD64		sym_table		= 0;
	bool		initialized		= false;
	bool		is_ready		= false;

public:

	~SymbolParser();

	bool Cleanup();

	bool Initialize(const SymbolLoader* loader);

	DWORD GetSymbolAddress(const wchar_t* sym_name);

	template <typename T>
	void* GetNTSymbolAddress(const wchar_t* sym_name, T& func)
	{
		DWORD rva = GetSymbolAddress(sym_name);

		if (!rva)
		{
			return 0;
		}

		func = (T)((BYTE*)nt_handle + rva);

		return (BYTE*)nt_handle + rva;
	}

	bool IsReady();
};