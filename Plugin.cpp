﻿#include "framework.h"
#include "ConstEncrypt.h"

//#define DeleteAntiQiapiaoObject

#define Get8(p) (*(const UINT8 *)(const void *)(p))
#define Get16(p) (*(const UINT16 *)(const void *)(p))
#define Get32(p) (*(const UINT32 *)(const void *)(p))
#define Get64(p) (*(const UINT64 *)(const void *)(p))

#define Set8(p, v) { *(UINT8 *)(p) = (v); }
#define Set16(p, v) { *(UINT16 *)(p) = (v); }
#define Set32(p, v) { *(UINT32 *)(p) = (v); }
#define Set64(p, v) { *(UINT64 *)(p) = (v); }

//相对寻址
_inline UINT_PTR RelativeAddressing8(UINT_PTR a)
{
	return (INT_PTR)*(INT8*)a + a + sizeof(INT8);
}
_inline UINT_PTR RelativeAddressing32(UINT_PTR a)
{
	return (INT_PTR)*(INT32*)a + a + sizeof(INT32);
}


UINT_PTR g_TimerID;

namespace QQSpeed
{
	HWND MainWindow = NULL;
	HMODULE Module_TopKart = 0;
	UINT_PTR Memory_Base = 0; //CGameMain
	UINT_PTR Memory_Base_PlayerMgr = 0; //CNxPlayerMgr
	UINT_PTR Memory_Base_PlayerMgr_Self = 0; //CNxPlayer
	UINT_PTR Memory_Player_Kart = 0;
	UINT_PTR Memory_Kart_Phys = 0;
	UINT_PTR Memory_Kart_Phys_Param = 0; //CCoreKart CDriftCenter
	UINT_PTR Memory_Kart_Phys_Param_AntiQiapiao = 0;
	UINT_PTR Memory_Kart_Phys_Param_AntiQiapiao_Enable = 0;

	void memoryEncrypt(int* key, char* data, int len)
	{
		char v3, v6;
		v6 = *data ^ *(char*)key;
		for (int i = 1; i < len; ++i)
		{
			v3 = data[i] ^ ((char*)key)[i % 4];
			data[i] = v6;
			v6 = v3;
		}
		*data = v6;
	}

	void memoryDecrypt(int* key, char* data, int len)
	{
		char v3, v6;
		v6 = *data ^ ((char*)key)[(len - 1) % 4];
		for (int i = len - 1; i; --i)
		{
			v3 = data[i] ^ ((char*)key)[(i - 1) % 4];
			data[i] = v6;
			v6 = v3;
		}
		*data = v6;
	}

	UINT_PTR getObject(UINT_PTR CallAddr, UINT_PTR This)
	{
		return ((UINT_PTR(__thiscall*)(UINT_PTR)) CallAddr)(This);
	}

#pragma pack(push, 8)
	class EncryptBoolPtr
	{
	public:
		int key;
		BOOL* data; // 2022年03月 从 BOOL 变成 BOOL*

		void set(BOOL value)
		{
			//改值应该顺便更新key, 这里不做更新
			QQSpeed::memoryEncrypt(&key, (char*)&value, sizeof(BOOL));
			*data = value;
		}

		BOOL get()
		{
			BOOL value = *data;
			QQSpeed::memoryDecrypt(&key, (char*)&value, sizeof(BOOL));
			return value;
		}
	};
#pragma pack(pop)
	static_assert(sizeof(BOOL) == 4, "错误的大小");
#if defined(_M_IX86)
	static_assert(sizeof(EncryptBoolPtr) == 8, "错误的结构大小");
#elif defined(_M_AMD64)
	static_assert(sizeof(EncryptBoolPtr) == 16, "错误的结构大小");
#endif
}

void CALLBACK Timer_AntiAntiQiapiao(HWND hwnd, UINT message, UINT_PTR iTimerID, DWORD dwTimer)
{
#if defined(_M_IX86)
	UINT_PTR p = QQSpeed::getObject(QQSpeed::Memory_Base, NULL);
	if (p) {
		p = QQSpeed::getObject(Get32(Get32(p) + QQSpeed::Memory_Base_PlayerMgr), p);
		p = QQSpeed::getObject(Get32(Get32(p) + QQSpeed::Memory_Base_PlayerMgr_Self), p);
		if (p) {
			p = Get32(p + QQSpeed::Memory_Player_Kart);
			p = QQSpeed::getObject(QQSpeed::Memory_Kart_Phys, p);
			if (p) {
				p = QQSpeed::getObject(QQSpeed::Memory_Kart_Phys_Param, p);
				if (p) {
#ifdef DeleteAntiQiapiaoObject
					UINT temp = Get32(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao);
					if (temp)
					{
						Set32(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao, NULL);
						delete (PVOID)temp;
						//MessageBoxA(QQSpeed::MainWindow, "已删除反卡漂对象！", "debug", MB_OK);
					}
#else
					p = Get32(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao);
					if (p)
					{
						QQSpeed::EncryptBoolPtr* EncryptData = (QQSpeed::EncryptBoolPtr*)(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao_Enable);
						EncryptData->set(FALSE); //禁用反卡漂
					}
#endif
				}
			}
		}
	}
#elif defined(_M_AMD64)
	UINT_PTR p = QQSpeed::getObject(QQSpeed::Memory_Base, NULL);
	if (p) {
		p = QQSpeed::getObject(Get64(Get64(p) + QQSpeed::Memory_Base_PlayerMgr), p);
		p = QQSpeed::getObject(Get64(Get64(p) + QQSpeed::Memory_Base_PlayerMgr_Self), p);
		if (p) {
			p = Get64(p + QQSpeed::Memory_Player_Kart);
			p = QQSpeed::getObject(QQSpeed::Memory_Kart_Phys, p);
			if (p) {
				p = QQSpeed::getObject(QQSpeed::Memory_Kart_Phys_Param, p);
				if (p) {
#ifdef DeleteAntiQiapiaoObject
					UINT temp = Get64(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao);
					if (temp)
					{
						Set64(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao, NULL);
						delete (PVOID)temp;
						//MessageBoxA(QQSpeed::MainWindow, "已删除反卡漂对象！", "debug", MB_OK);
					}
#else
					p = Get64(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao);
					if (p)
					{
						QQSpeed::EncryptBoolPtr* EncryptData = (QQSpeed::EncryptBoolPtr*)(p + QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao_Enable);
						EncryptData->set(FALSE); //禁用反卡漂
					}
#endif
				}
			}
		}
	}
#endif
}

void CALLBACK Timer_Init(HWND hwnd, UINT message, UINT_PTR iTimerID, DWORD dwTimer)
{
	//KillTimer(hwnd, iTimerID);
	SetTimer(hwnd, iTimerID, 1300, Timer_AntiAntiQiapiao);
}

//Array Of Byte Scan
UINT_PTR AOBScan(const char* Data, int DataLen, const char* Pattern, int PatternLen, const char* Mask) {
	int i, k;
	DataLen = (DataLen - PatternLen) + 1;
	for (i = 0; i < DataLen; i++) {
		for (k = 0; k < PatternLen; k++) {
			if (!(Mask[k] != 0 || Pattern[k] == (Data[k]))) {
				goto label;
			}
		}
		return (UINT_PTR)Data;
	label:
		Data++;
	}
	return 0;
}

UINT_PTR AOBScanModule(HMODULE hModule, DWORD Protect, int PatternLen, const char* Pattern, const char* Mask) {
	PIMAGE_NT_HEADERS PE = (PIMAGE_NT_HEADERS)((UINT_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	WORD SectionsNum = PE->FileHeader.NumberOfSections;
	WORD OptionalHeaderSize = PE->FileHeader.SizeOfOptionalHeader;
	PIMAGE_SECTION_HEADER Section = (PIMAGE_SECTION_HEADER)((LPBYTE)PE + 4 + sizeof(IMAGE_FILE_HEADER) + OptionalHeaderSize);
	UINT_PTR Result = 0;
	int Length = 0;
	int i;
	for (i = 0; SectionsNum > i; i++) {
		if ((Section->Characteristics & Protect) != 0) {
			Result = (UINT_PTR)hModule + Section->VirtualAddress;
			Length = Section->Misc.VirtualSize;
			Result = AOBScan((char*)Result, Length, Pattern, PatternLen, Mask);
			if (Result) {
				break;
			}
		}
		Section++;
	}
	return Result;
}


DWORD WINAPI InitPlugin(LPVOID lpThreadParameter)
{
	HWND hWnd = 0;
	DWORD PID = 0;

	//获取主窗口句柄
	do {
		while ((hWnd = FindWindowExW(0, hWnd, XorString(L"GAMEAPP"), NULL)) == NULL) {
			Sleep(500);
		}
		GetWindowThreadProcessId(hWnd, &PID);
	} while (PID != GetCurrentProcessId());
	QQSpeed::MainWindow = hWnd;

	//获取模块基址
	UINT_PTR Result, Address;
	DWORD Reason;
	do
	{
		Sleep(1000);
		QQSpeed::Module_TopKart = GetModuleHandleW(XorString(L"Top-Kart.dll"));
	} while (QQSpeed::Module_TopKart == NULL);

	//特征码定位
	do
	{
#if defined(_M_IX86)
		//2024-03-05
		//E8 ???????? 8B C8 8B 10 FF 52 ?? 8B C8 8B 10 FF 92 ????0000 8B 88 ????0000 E8 ???????? 8B C8 E8 ???????? 8B C8 E8
		Result = AOBScanModule(QQSpeed::Module_TopKart, IMAGE_SCN_CNT_CODE, 43,
			"\xE8\x00\x00\x00\x00\x8B\xC8\x8B\x10\xFF\x52\x00\x8B\xC8\x8B\x10\xFF\x92\x00\x00\x00\x00\x8B\x88\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\xE8\x00\x00\x00\x00\x8B\xC8\xE8",
			"\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\xFF\x00\x00\x00\x00\x00\x00\xFF\xFF\x00\x00\x00\x00\xFF\xFF\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00");
		if (Result == 0) {
			Reason = 1;
			break;
		}
		else {
			Address = Result;
			Address = RelativeAddressing32(Address + 1);
			QQSpeed::Memory_Base = Address; //函数

			Address = Result + 5 + 2 + 2;
			QQSpeed::Memory_Base_PlayerMgr = Get8(Address + 2); //虚函数

			Address = Result + 5 + 2 + 2 + 3 + 2 + 2;
			QQSpeed::Memory_Base_PlayerMgr_Self = Get32(Address + 2); //虚函数

			Address = Result + 5 + 2 + 2 + 3 + 2 + 2 + 6;
			QQSpeed::Memory_Player_Kart = Get32(Address + 2); //偏移

			Address = Result + 5 + 2 + 2 + 3 + 2 + 2 + 6 + 6;
			Address = RelativeAddressing32(Address + 1);
			QQSpeed::Memory_Kart_Phys = Address; //函数

			Address = Result + 5 + 2 + 2 + 3 + 2 + 2 + 6 + 6 + 5 + 2;
			Address = RelativeAddressing32(Address + 1);
			QQSpeed::Memory_Kart_Phys_Param = Address; //函数
		}

		QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao = 0x4C;
		QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao_Enable = 0x48;
#elif defined(_M_AMD64)
		//E8 ???????? 48 8B C8 48 8B 10 FF 52 ?? 48 8B C8 48 8B 10 FF 92 ????0000 48 8B 88 ????0000 E8 ???????? 48 8B C8 E8 ???????? 48 8B C8 E8
		Result = AOBScanModule(QQSpeed::Module_TopKart, IMAGE_SCN_CNT_CODE, 50,
			"\xE8\x00\x00\x00\x00\x48\x8B\xC8\x48\x8B\x10\xFF\x52\x00\x48\x8B\xC8\x48\x8B\x10\xFF\x92\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xC8\xE8\x00\x00\x00\x00\x48\x8B\xC8\xE8",
			"\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\x00\x00\x00\x00\x00\xFF\xFF\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00");
		if (Result == 0) {
			Reason = 1;
			break;
		}
		else {
			Address = Result;
			Address = RelativeAddressing32(Address + 1);
			QQSpeed::Memory_Base = Address; //函数

			Address = Result + 5 + 3 + 3;
			QQSpeed::Memory_Base_PlayerMgr = Get8(Address + 2); //虚函数

			Address = Result + 5 + 3 + 3 + 3 + 3 + 3;
			QQSpeed::Memory_Base_PlayerMgr_Self = Get32(Address + 2); //虚函数

			Address = Result + 5 + 3 + 3 + 3 + 3 + 3 + 6;
			QQSpeed::Memory_Player_Kart = Get32(Address + 3); //偏移

			Address = Result + 5 + 3 + 3 + 3 + 3 + 3 + 6 + 7;
			Address = RelativeAddressing32(Address + 1);
			QQSpeed::Memory_Kart_Phys = Address; //函数

			Address = Result + 5 + 3 + 3 + 3 + 3 + 3 + 6 + 7 + 5 + 3;
			Address = RelativeAddressing32(Address + 1);
			QQSpeed::Memory_Kart_Phys_Param = Address; //函数
		}

		QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao = 0x90;
		QQSpeed::Memory_Kart_Phys_Param_AntiQiapiao_Enable = 0x90;
#else
#error 仅支持x86和x64
#endif
		g_TimerID = (UINT_PTR)&Timer_Init;
		SetTimer(QQSpeed::MainWindow, g_TimerID, 1, Timer_Init);//有些操作必须在主线程执行
		return 0;
	} while (false);
	wchar_t string[1024];
	wsprintfW(string, XorString(L"未适配当前游戏版本！错误代码：%d"), Reason);
	MessageBoxW(hWnd, string, XorString(L"卡漂插件"), MB_OK);
	return Reason;
}
