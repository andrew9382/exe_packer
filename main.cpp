#include "includes.h"

#ifdef _WIN64
const wchar_t file_path[] = L"D:\\Programming\\projects\\ConsoleApplication1\\x64\\Debug\\ConsoleApplication1.exe";
#else
const wchar_t file_path[] = L"D:\\Programming\\projects\\ConsoleApplication1\\Debug\\ConsoleApplication1.exe";
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