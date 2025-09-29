#include <Windows.h>
#include "scan.hpp"
#include "Minhook/MinHook.h"
#pragma comment(lib, "libMinHook.x86.lib")

#define SEARCH_PATH_COUNT 1

const char* search_paths[SEARCH_PATH_COUNT] = { "custom" };

#define REMOVE_QUOTES(str) REMOVE_QUOTES_IMPL str
#define REMOVE_QUOTES_IMPL(x) x
#define scan_for_signature(mod, sig, dest) dest = (DWORD)ScanModule(mod, sig);
// ^^ yeah i know this is excessive for only being used twice, its taken from the larger patching framework im working on

std::string ExeDir;

HMODULE Dll = NULL;

using CreateInterface_t = DWORD (*)(const char* pName, int* pReturnCode);
CreateInterface_t CreateInterfaceInternal;

using FindFile_t = DWORD(__thiscall*)(DWORD, DWORD, const char*, const char*, int, char**, bool);
using FileExists_t = bool(__thiscall*)(DWORD, const char*, const char*);

DWORD FindFile_adr;
DWORD FileExists_adr;
FindFile_t FindFile_og;
FileExists_t FileExists_og;

std::vector<std::string> g_args;

void scan_for_custom_asset(char** filename) {
	for (int i = 0; i < SEARCH_PATH_COUNT; i++) {
		std::string targetFile = ExeDir + "\\" + search_paths[i] + "\\" + *filename;
		DWORD fileAttr = GetFileAttributesA(targetFile.c_str());
		if (fileAttr != INVALID_FILE_ATTRIBUTES && !(fileAttr & FILE_ATTRIBUTE_DIRECTORY)) {
			*filename = (char*)targetFile.c_str();
			break;
		}
	}
}

DWORD __fastcall FindFile(DWORD t, void* ecx, DWORD p, char* fn, const char* o, int f, char** r, bool c) {
	scan_for_custom_asset(&fn);
	return FindFile_og(t, p, fn, o, f, r, c);
}

bool __fastcall FileExists(DWORD _this, void* ecx, char* fn, const char* b) {
	scan_for_custom_asset(&fn);
	return FileExists_og(_this, fn, b);
}

extern "C" __declspec(dllexport) DWORD CreateInterface(const char* pName, int* pReturnCode)
{
	return CreateInterfaceInternal(pName, pReturnCode);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	if (Dll == NULL) {
		int argc = 0;
		LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

		if (argv) {
			for (int i = 0; i < argc; ++i) {
				int size_needed = WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, NULL, 0, NULL, NULL);
				std::string arg(size_needed - 1, 0);
				WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, &arg[0], size_needed, NULL, NULL);
				g_args.push_back(arg);
			}
			free(argv);
		}

		char buffer[MAX_PATH];
		GetModuleFileName(NULL, buffer, MAX_PATH);
		std::string pathStr(buffer);
		size_t pos = pathStr.find_last_of("\\/");
		ExeDir = (pos != std::string::npos) ? pathStr.substr(0, pos) : pathStr;

		for (int argn = 0; argn < g_args.size(); argn++) {
			std::string arg = g_args[argn];
			if (arg == "-game" && g_args[argn + 1] != "portal2") {
				// sourcemod
				ExeDir = g_args[argn + 1];
				break;
			}
		}

		Dll = LoadLibraryA(".\\bin\\filesystem_stdio_og.dll");
		CreateInterfaceInternal = (CreateInterface_t)GetProcAddress(Dll, "CreateInterface");
		MH_Initialize();

		scan_for_signature(Dll, "55 8B EC 81 EC 48", FindFile_adr);
		MH_CreateHook((DWORD*)FindFile_adr, FindFile, (LPVOID*)&FindFile_og);

		scan_for_signature(Dll, "55 8B EC 81 EC 60 01 00 00 53 56 8B F1 8B 0D ?? ?? ?? ?? 33", FileExists_adr);
		MH_CreateHook((DWORD*)FileExists_adr, FileExists, (LPVOID*)&FileExists_og);
		MH_EnableHook(MH_ALL_HOOKS);
	}
	return 1;
}