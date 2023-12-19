#pragma once

#define NT_DLL_NAME_INIT(arr)					arr[0] = 'n'; arr[1] = 't'; arr[2] = 'd'; arr[3] = 'l'; arr[4] = 'l'; arr[5] = '.'; arr[6] = 'd'; arr[7] = 'l'; arr[8] = 'l'; arr[9] = '\0'
#define NT_DLL_NAME_INIT_UNICODE(arr)			arr[0] = L'n'; arr[1] = L't'; arr[2] = L'd'; arr[3] = L'l'; arr[4] = L'l'; arr[5] = L'.'; arr[6] = L'd'; arr[7] = L'l'; arr[8] = L'l'; arr[9] = L'\0'
#define KERNEL_DLL_NAME_INIT_UNICODE(arr)		arr[0] = L'K'; arr[1] = L'E'; arr[2] = L'R'; arr[3] = L'N'; arr[4] = L'E'; arr[5] = L'L'; arr[6] = L'3'; arr[7] = L'2'; arr[8] = L'.'; arr[9] = L'D'; arr[10] = L'L'; arr[11] = L'L'; arr[12] = L'\0'
#define COMPRESSED_SECTION_NAME_INIT(arr)		arr[0] = '.'; arr[1] = 'f'; arr[2] = 'u'; arr[3] = 'c'; arr[4] = 'k'; arr[5] = '_'; arr[6] = 'u'; arr[7] = '\0'
#define ENCRYPTION_KEY_INIT(arr)				arr[0] = 'q'; arr[1] = 'w'; arr[2] = 'e'; arr[3] = 'r'; arr[4] = 't'; arr[5] = 'y'; arr[6] = '1'; arr[7] = '4'; arr[8] = '8'; arr[9] = '8'; arr[10] = '\0'
#define IMPORT_NAMES_SECTION_INIT(arr)			arr[0] = '.'; arr[1] = 'd'; arr[2] = 'a'; arr[3] = 't'; arr[4] = 'a'; arr[5] = '\0'
#define LOAD_LIBRARY_STR_INIT(arr)				arr[0] = 'L'; arr[1] = 'o'; arr[2] = 'a'; arr[3] = 'd'; arr[4] = 'L'; arr[5] = 'i'; arr[6] = 'b'; arr[7] = 'r'; arr[8] = 'a'; arr[9] = 'r'; arr[10] = 'y'; arr[11] = 'A'; arr[12] = '\0'

#define NT_DLL_NAME_SIZE					10
#define KERNEL_DLL_NAME_SIZE				13
#define COMPRESSED_SECTION_NAME_SIZE		8
#define ENTRYPTYON_KEY_SIZE					11
#define IMPORT_NAMES_SECTION_SIZE			6
#define LOAD_LIBRARY_STR_SIZE				13