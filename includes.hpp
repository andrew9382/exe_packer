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
#include <memory>
#include "strings_init.hpp"
#include "namespaces.hpp"
#include "tools.hpp"
#include "nt_defs.h"
#include "nt_funcs.h"
#include "pack_file.hpp"
#include "huffman_compressor_internal.hpp"
#include "unpacker_stub.hpp"
#include "huffman_decompressor_stub.hpp"

#pragma warning(disable : 4996)