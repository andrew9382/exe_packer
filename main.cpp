#include "includes.h"

#ifdef _WIN64
const wchar_t file_path[] = L"C:\\Users\\Andrew\\Desktop\\Programming\\cpp\\garbage\\test_for_injection\\x64\\Release\\test_for_injection.exe";
#else
const wchar_t file_path[] = L"C:\\Users\\Andrew\\Desktop\\Programming\\cpp\\garbage\\test_for_injection\\Release\\test_for_injection.exe";
#endif

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	if (!AllocConsole())
	{
		return 1;
	}

	if (!SetConsoleTitleW(L"exe_packer.exe"))
	{
		return 1;
	}

	FILE* con_out = nullptr;
	if (freopen_s(&con_out, "CONOUT$", "w", stdout) || !con_out)
	{
		if (con_out)
		{
			fclose(con_out);
		}

		return 1;
	}

	if (!PackFile(file_path))
	{
		fclose(con_out);

		return 1;
	}

	fclose(con_out);
	
	return 0;
}