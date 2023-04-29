#pragma once
#include <Windows.h>

//Call original function
#define CallUnhooked(retBuffer, hookptr, func) \
    hookptr->disable();\
    retBuffer = func;\
    hookptr->enable()\

const char MOV = 0xB8;
const char RAX = 0x48;
const char PUSH_RAX = 0x50;
const char RET = 0xC3;

//NULL BYTES are where address of hook func will go later
const int ADDR_SIZE = sizeof(void*);
#if _WIN64
//
//  64-bit
//
const int PATCH_LEN = 2 + ADDR_SIZE + 2;
//"movabs rax,<address of hook function>; push rax; ret"
const char ASM_SRC[12] = { RAX, MOV, 0,0,0,0,0,0,0,0, PUSH_RAX, RET };
const int ADDR_OFFSET = 2;
#else
//
//  32-bit
//
const int P_LEN = 1 + ADDR_SIZE + 2;
//"mov eax,<address of hook function>; push eax; ret"
const char ASM_SRC[7] = { MOV, 0,0,0,0, PUSH_RAX, RET };
const int ADDR_OFFSET = 1;
#endif

//Author: Complexicon

struct Hook {
	void* funcAddr = 0;
    char patchBytes[PATCH_LEN] = { 0 };
    char origBytes[PATCH_LEN] = { 0 };
	DWORD memProtection;

	//Setup Hook struct
	Hook(const char* module, const char* function, void* hookFunction) {

		// get address of the function in memory
		funcAddr = GetProcAddress(LoadLibraryA(module), function);

		// orig PATCH_LEN bytes
		memcpy_s(origBytes, PATCH_LEN, funcAddr, PATCH_LEN);

		// create a patch from ASM_SRC
		memcpy_s(patchBytes, PATCH_LEN, ASM_SRC, PATCH_LEN);
		memcpy_s(patchBytes + ADDR_OFFSET, ADDR_SIZE, &hookFunction, ADDR_SIZE);
	}

	//Enable the Hook
	bool enable() {
		VirtualProtect(funcAddr, PATCH_LEN, PAGE_EXECUTE_READWRITE, &memProtection);
		memcpy_s(funcAddr, PATCH_LEN, patchBytes, PATCH_LEN);
		VirtualProtect(funcAddr, PATCH_LEN, memProtection, &memProtection);
		return true;
	}

	//Disable the Hook
	bool disable() {
		VirtualProtect(funcAddr, PATCH_LEN, PAGE_EXECUTE_READWRITE, &memProtection);
		memcpy_s(funcAddr, PATCH_LEN, origBytes, PATCH_LEN);
		VirtualProtect(funcAddr, PATCH_LEN, memProtection, &memProtection);
		return true;
	}

};