#pragma once

#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <WinInet.h>
#include <dbghelp.h>
#include <locale>
#include <codecvt>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <queue>
#include "strings_init.h"
#include "namespaces.h"
#include "tools.h"
#include "nt_defs.h"
#include "nt_funcs.h"
#include "pack_file.h"
#include "huffman_compressor_internal.h"
#include "unpacker_stub.h"
#include "huffman_decompressor_stub.h"

#pragma warning(disable : 4996)