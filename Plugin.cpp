#include "framework.h"
#include "MinHook/MinHook.h"
#pragma comment(lib, "libMinHook.lib")
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)


#define Get8(p) (*(const UINT8 *)(const void *)(p))
#define Get16(p) (*(const UINT16 *)(const void *)(p))
#define Get32(p) (*(const UINT32 *)(const void *)(p))
#define Get64(p) (*(const UINT64 *)(const void *)(p))
#define GetPtr(p) (*(const UINT_PTR *)(const void *)(p))

#define Set8(p, v) { *(UINT8 *)(p) = (v); }
#define Set16(p, v) { *(UINT16 *)(p) = (v); }
#define Set32(p, v) { *(UINT32 *)(p) = (v); }
#define Set64(p, v) { *(UINT64 *)(p) = (v); }
#define SetPtr(p, v) { *(UINT_PTR *)(p) = (v); }


//相对寻址
_inline UINT_PTR RelativeAddressing8(UINT_PTR a)
{
	return (INT_PTR)*(INT8*)a + a + sizeof(INT8);
}
_inline UINT_PTR RelativeAddressing32(UINT_PTR a)
{
	return (INT_PTR)*(INT32*)a + a + sizeof(INT32);
}

void my_wprintf(const wchar_t* format, ...)
{
	va_list ap;
	va_start(ap, format);
	wchar_t buffer[1024];
	memset(buffer, 0, sizeof(buffer));
	int length = wvsprintfW(buffer, format, ap);
	va_end(ap);
	WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), buffer, length, NULL, NULL);
}

UINT_PTR g_TimerID;

namespace QQSpeed
{
	HWND MainWindow = NULL;
	DWORD MainThreadID = 0;
	HMODULE Module_TopKart = 0;
	DWORD Module_TopKart_Size = 0;

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

namespace qiapiao_1
{
	UINT_PTR Memory_Base = 0; //CGameMain
	UINT_PTR Memory_Base_PlayerMgr = 0; //CNxPlayerMgr
	UINT_PTR Memory_Base_PlayerMgr_Self = 0; //CNxPlayer
	UINT_PTR Memory_Player_Kart = 0;
	UINT_PTR Memory_Kart_Phys = 0;
	UINT_PTR Memory_Kart_Phys_Param = 0; //CCoreKart CDriftCenter
	UINT_PTR Memory_Kart_Phys_Param_AntiQiapiao = 0;
	UINT_PTR Memory_Kart_Phys_Param_AntiQiapiao_Enable = 0;
	void CALLBACK Timer_UnlockQiapiao(HWND hwnd, UINT message, UINT_PTR iTimerID, DWORD dwTimer)
	{
		UINT_PTR p = QQSpeed::getObject(Memory_Base, NULL);
		if(!p) return;
		p = QQSpeed::getObject(GetPtr(GetPtr(p) + Memory_Base_PlayerMgr), p);
		p = QQSpeed::getObject(GetPtr(GetPtr(p) + Memory_Base_PlayerMgr_Self), p);
		if(!p) return;
		p = GetPtr(p + Memory_Player_Kart);
		p = QQSpeed::getObject(Memory_Kart_Phys, p);
		if(!p) return;
		p = QQSpeed::getObject(Memory_Kart_Phys_Param, p);
		if(p)
		{
			UINT_PTR pAntiQiapiao = GetPtr(p + Memory_Kart_Phys_Param_AntiQiapiao);
			if (pAntiQiapiao)
			{
#ifdef DeleteAntiQiapiaoObject
				SetPtr(p + Memory_Kart_Phys_Param_AntiQiapiao, NULL);
				delete (PVOID)pAntiQiapiao;
#else
				QQSpeed::EncryptBoolPtr* EncryptData = (QQSpeed::EncryptBoolPtr*)(pAntiQiapiao + Memory_Kart_Phys_Param_AntiQiapiao_Enable);
				EncryptData->set(FALSE); //禁用反卡漂
#endif
			}
		}
	}
}

namespace qiapiao_2
{
	UINT_PTR Memory_Base = 0;
	UINT_PTR Memory_BaseOffset = 0;
	UINT_PTR Memory_2 = 0;
	UINT_PTR Memory_3 = 0;
	UINT_PTR Memory_4 = 0;
	UINT_PTR Memory_5 = 0;
	UINT_PTR Memory_6 = 0;
	UINT_PTR Memory_7 = 0;
	UINT_PTR Memory_AntiQiapiao = 0;
	UINT_PTR Memory_AntiQiapiao_Enable = 0;
	void CALLBACK Timer_UnlockQiapiao(HWND hwnd, UINT message, UINT_PTR iTimerID, DWORD dwTimer)
	{
		UINT_PTR p = GetPtr(Memory_Base);
		if(!p) return;
		p += Memory_BaseOffset;
		p = QQSpeed::getObject(GetPtr(GetPtr(p) + Memory_2), p);
		p = QQSpeed::getObject(GetPtr(GetPtr(p) + Memory_3), p);
		if(!p) return;
		p = GetPtr(p + Memory_4);
		p = GetPtr(p + Memory_5);
		if(!p) return;
		p = GetPtr(p + Memory_6);
		if(!p) return;
		p = QQSpeed::getObject(GetPtr(GetPtr(p) + Memory_7), p);
		if (p)
		{
			UINT_PTR pAntiQiapiao = GetPtr(p + Memory_AntiQiapiao);
			if (pAntiQiapiao)
			{
#ifdef DeleteAntiQiapiaoObject
				SetPtr(p + Memory_AntiQiapiao, NULL);
				delete (PVOID)pAntiQiapiao;
#else
				QQSpeed::EncryptBoolPtr* EncryptData = (QQSpeed::EncryptBoolPtr*)(pAntiQiapiao + Memory_AntiQiapiao_Enable);
				EncryptData->set(FALSE); //禁用反卡漂
#endif
			}
		}
	}

	void CALLBACK Timer_UnlockQiapiao2(HWND hwnd, UINT message, UINT_PTR iTimerID, DWORD dwTimer)
	{
		KillTimer(hwnd, iTimerID);
		UINT_PTR p = iTimerID;
		QQSpeed::EncryptBoolPtr* EncryptData = (QQSpeed::EncryptBoolPtr*)(p + 0x90);
		if (EncryptData->get() == 1)
		{
			//my_wprintf(L"ojbk!");
			EncryptData->set(0); //禁用反卡漂
		}
	}
}

void CALLBACK Timer_Init(HWND hwnd, UINT message, UINT_PTR iTimerID, DWORD dwTimer)
{
	if (qiapiao_1::Memory_Base)
		SetTimer(hwnd, iTimerID, 1300, qiapiao_1::Timer_UnlockQiapiao);
	if (qiapiao_2::Memory_Base)
		SetTimer(hwnd, iTimerID, 1300, qiapiao_2::Timer_UnlockQiapiao);
}

//Array Of Byte Scan
char* AOBScan(const char* bytes, size_t bytes_len, const char* pattern, size_t pattern_len, const char* mask)
{
	for (const char* tail = bytes + (bytes_len - pattern_len); bytes <= tail; bytes++)
	{
		for (size_t i = 0; i < pattern_len; i++)
			if (((bytes[i] ^ pattern[i]) & mask[i]) != 0) goto label;
		return (char*)bytes;
	label:;
	}
	return NULL;
}

UINT_PTR AOBScanModule(HMODULE hModule, DWORD section_characteristics, size_t pattern_len, const char* pattern, const char* mask)
{
	PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((UINT_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	WORD num = pe->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)((UINT_PTR)pe + sizeof(pe->Signature) + sizeof(IMAGE_FILE_HEADER) + pe->FileHeader.SizeOfOptionalHeader);
	for (WORD i = 0; num > i; i++, section++)
		if ((section->Characteristics & section_characteristics) != 0)
			if (UINT_PTR result = (UINT_PTR)AOBScan((char*)hModule + section->VirtualAddress, section->Misc.VirtualSize, pattern, pattern_len, mask))
				return result;
	return NULL;
}

__inline DWORD GetModuleCompileTime(HMODULE hModule)
{
	PIMAGE_NT_HEADERS pe = (PIMAGE_NT_HEADERS)((UINT_PTR)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	return pe->FileHeader.TimeDateStamp;
}
__inline DWORD GetModuleSize(HANDLE hModule)
{
	IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)hModule;
	IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)dos + dos->e_lfanew);
	return nt->OptionalHeader.SizeOfImage;
}

#define IsModuleAddress(Address, ModuleBase, ModuleSize) ((size_t)Address > (size_t)ModuleBase && (size_t)Address < (size_t)ModuleBase+ModuleSize)



void* (*original_malloc)(size_t size) = NULL;
void* hooked_malloc(size_t size)
{
	void* address = _ReturnAddress();
	if (IsModuleAddress(address, QQSpeed::Module_TopKart, QQSpeed::Module_TopKart_Size) && GetCurrentThreadId() == QQSpeed::MainThreadID)
	{
		static UINT_PTR address2 = NULL;
		address = original_malloc(size);
		//my_wprintf(L"[DEBUG]%p %u\n", address, size);

		/* 需要检测的目标序列（按调用顺序） */
		static const int target_seq[] = {
			192, 24, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4
		};

		/* 目标序列长度 */
		const int seq_len = sizeof(target_seq)/sizeof(target_seq[0]);

		/* 当前已经匹配到的第几个元素(0~seq_len) */
		static int cur_index = 0;

		/* 检查当前传入的参数是否与预期序列匹配 */
		if (size == target_seq[cur_index]) {
			if (cur_index == 0) // 第一次
			{
				address2 = (UINT_PTR)address;
			}
			/* 匹配上了，指针后移 */
			cur_index++;
			/* 完整匹配到整个序列 */
			if (cur_index == seq_len) {
				//my_wprintf(L"已检测到序列！%p\n", address2);
				cur_index = 0;
				SetTimer(QQSpeed::MainWindow, address2, 3000, qiapiao_2::Timer_UnlockQiapiao2);
			}
		} else {
			/* 任何一次不匹配都会把状态恢复到起点 */
			cur_index = 0;
		}

		return address;
	}
	return original_malloc(size);
}

//__declspec(dllexport)
void InitHook()
{
#if defined(_M_IX86)
	MessageBoxTimeoutW(QQSpeed::MainWindow, XorString(L"未兼容x86"), XorString(L"卡漂插件"), MB_OK, 0, 5000);
	return;
#endif
	QQSpeed::Module_TopKart_Size = GetModuleSize(QQSpeed::Module_TopKart);
	/*
	if (AllocConsole())
	{
		ShowWindow(GetConsoleWindow(), SW_SHOWNA);
	}
	*/
	if (MH_Initialize() != MH_OK)
		return;
	if (MH_CreateHook(malloc, hooked_malloc, (LPVOID *)&original_malloc) != MH_OK)
		return;
	if (MH_EnableHook(malloc) != MH_OK)
		return;
	/* 清理
	MH_DisableHook(malloc);
	MH_RemoveHook(malloc);
	MH_Uninitialize();
	*/
}

DWORD WINAPI InitPlugin(LPVOID lpThreadParameter)
{
	HWND hWnd = 0;
	DWORD PID = 0;
	DWORD TID = 0;
	UINT_PTR Result, Address;
	DWORD time, reason;
	wchar_t string[1024];

	//获取主窗口句柄
	do {
		while ((hWnd = FindWindowExW(0, hWnd, XorString(L"GAMEAPP"), NULL)) == NULL) {
			Sleep(500);
		}
		TID = GetWindowThreadProcessId(hWnd, &PID);
	} while (PID != GetCurrentProcessId());
	QQSpeed::MainWindow = hWnd;
	QQSpeed::MainThreadID = TID;

	//获取模块基址
	do
	{
		Sleep(1000);
		QQSpeed::Module_TopKart = GetModuleHandleW(XorString(L"Top-Kart.dll"));
	} while (QQSpeed::Module_TopKart == NULL);

	//通过特征码定位
	time = GetModuleCompileTime(QQSpeed::Module_TopKart);
	do
	{
#if defined(_M_IX86)
		if (time < 1333238400) // 2012-04-01
		{
			// 更旧的版本未封禁卡漂
			reason = 4;
			break;
		}
		else if (time > 1682553600) // 2023-04-27
		{
			//适用于 Beta83 熔炉盛典 Date:2023-04-28
			//E8 ???????? 8B C8 8B 10 FF 52 ?? 8B C8 8B 10 FF 92 ????0000 8B 88 ????0000 E8 ???????? 8B C8 E8 ???????? 8B C8 E8
			Result = AOBScanModule(QQSpeed::Module_TopKart, IMAGE_SCN_CNT_CODE, 43,
				"\xE8\x00\x00\x00\x00\x8B\xC8\x8B\x10\xFF\x52\x00\x8B\xC8\x8B\x10\xFF\x92\x00\x00\x00\x00\x8B\x88\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\xE8\x00\x00\x00\x00\x8B\xC8\xE8",
				"\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF");
			if (Result == 0) {
				reason = 1;
				break;
			}
			else {
				Address = Result;
				Address = RelativeAddressing32(Address + 1);
				qiapiao_1::Memory_Base = Address; //函数

				Address = Result + 9;
				qiapiao_1::Memory_Base_PlayerMgr = Get8(Address + 2); //虚函数

				Address = Result + 16;
				qiapiao_1::Memory_Base_PlayerMgr_Self = Get32(Address + 2); //虚函数

				Address = Result + 22;
				qiapiao_1::Memory_Player_Kart = Get32(Address + 2); //偏移

				Address = Result + 28;
				Address = RelativeAddressing32(Address + 1);
				qiapiao_1::Memory_Kart_Phys = Address; //函数

				Address = Result + 35;
				Address = RelativeAddressing32(Address + 1);
				qiapiao_1::Memory_Kart_Phys_Param = Address; //函数
			}
			qiapiao_1::Memory_Kart_Phys_Param_AntiQiapiao = 0x4C;
			qiapiao_1::Memory_Kart_Phys_Param_AntiQiapiao_Enable = 0x48;
		}
		else if (time > 1450310400) // 2015-12-17
		{
			//这通常是私服才能登录旧版本，且似乎没有CRC检测，所以如此这般
			//适用于 Beta28 辉煌之路 ~ Beta82 龙晶大闯关
/*
Top-Kart.dll+2D8CB - C6 45 FB 00           - mov byte ptr [ebp-05],00
Top-Kart.dll+2D8CF - C7 45 F0 01000000     - mov [ebp-10],00000001 { 是否封禁卡漂,改0解 }
Top-Kart.dll+2D8D6 - 8D 45 F0              - lea eax,[ebp-10]
Top-Kart.dll+2D8D9 - 50                    - push eax
Top-Kart.dll+2D8DA - 8B 4D C0              - mov ecx,[ebp-40]
Top-Kart.dll+2D8DD - 83 C1 4C              - add ecx,4C
Top-Kart.dll+2D8E0 - E8 8E494002           - call Top-Kart.dll+2432273
Top-Kart.dll+2D8E5 - C6 45 FB 01           - mov byte ptr [ebp-05],01
*/
			//C6 45 ?? 00 C7 45 ?? 01000000 8D 45 ?? 50 8B 4D ?? 83 C1 ?? E8
			Result = AOBScanModule(QQSpeed::Module_TopKart, IMAGE_SCN_CNT_CODE, 22,
				"\xC6\x45\x00\x00\xC7\x45\x00\x01\x00\x00\x00\x8D\x45\x00\x50\x8B\x4D\x00\x83\xC1\x00\xE8",
				"\xFF\xFF\x00\xFF\xFF\xFF\x00\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xFF\xFF\x00\xFF\xFF\x00\xFF");
			if (Result == 0) {
				reason = 3;
				break;
			}
			else {
				int* p = (int*)(Result + 7);
				DWORD oldProtect;
				VirtualProtect(p, sizeof(int), PAGE_EXECUTE_READWRITE, &oldProtect);
				*p = 0;
				VirtualProtect(p, sizeof(int), oldProtect, &oldProtect);
				return 0;
			}
		}
		else
		{
			// 不支持
			reason = 2;
			break;
		}
#elif defined(_M_AMD64)
/*
		if (time < 1756166400) // 2025-08-26
		{
			// 适用于 Beta88 幻域大闯关 Date:2024-03-05
			// 不支持 Beta96 Ver19994 Date:2025-06-24, 但支持 Beta96 Ver20009 Date:2025-07-01
			// E8 ???????? 48 8B C8 48 8B 10 FF 52 ?? 48 8B C8 48 8B 10 FF 92 ????0000 48 8B 88 ????0000 E8 ???????? 48 8B C8 E8 ???????? 48 8B C8 E8
			Result = AOBScanModule(QQSpeed::Module_TopKart, IMAGE_SCN_CNT_CODE, 50,
				"\xE8\x00\x00\x00\x00\x48\x8B\xC8\x48\x8B\x10\xFF\x52\x00\x48\x8B\xC8\x48\x8B\x10\xFF\x92\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xC8\xE8\x00\x00\x00\x00\x48\x8B\xC8\xE8",
				"\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF");
			if (Result == 0) {
				reason = 1;
				break;
			}
			else {
				Address = Result;
				Address = RelativeAddressing32(Address + 1);
				qiapiao_1::Memory_Base = Address; //函数

				Address = Result + 11;
				qiapiao_1::Memory_Base_PlayerMgr = Get8(Address + 2); //虚函数

				Address = Result + 20;
				qiapiao_1::Memory_Base_PlayerMgr_Self = Get32(Address + 2); //虚函数

				Address = Result + 26;
				qiapiao_1::Memory_Player_Kart = Get32(Address + 3); //偏移

				Address = Result + 33;
				Address = RelativeAddressing32(Address + 1);
				qiapiao_1::Memory_Kart_Phys = Address; //函数

				Address = Result + 41;
				Address = RelativeAddressing32(Address + 1);
				qiapiao_1::Memory_Kart_Phys_Param = Address; //函数
			}
			qiapiao_1::Memory_Kart_Phys_Param_AntiQiapiao = 0x90;
			qiapiao_1::Memory_Kart_Phys_Param_AntiQiapiao_Enable = 0x90;
		}
		else
		{
			// 适用于 Beta98 未测试上一个版本
			// 48 8B 05 ???????? 48 8D 88 ????0000 48 85 C0 75 03 48 8B CB 48 8B 01 FF 50 ?? 48 8B C8 48 8B 10 FF 92 ????0000 48 8B 88 ????0000 48 8B 41 ?? 48 8B 88 ????0000 48 8B 01 FF 90 ????0000
			Result = AOBScanModule(QQSpeed::Module_TopKart, IMAGE_SCN_CNT_CODE, 67,
				"\x48\x8B\x05\x00\x00\x00\x00\x48\x8D\x88\x00\x00\x00\x00\x48\x85\xC0\x75\x03\x48\x8B\xCB\x48\x8B\x01\xFF\x50\x00\x48\x8B\xC8\x48\x8B\x10\xFF\x92\x00\x00\x00\x00\x48\x8B\x88\x00\x00\x00\x00\x48\x8B\x41\x00\x48\x8B\x88\x00\x00\x00\x00\x48\x8B\x01\xFF\x90\x00\x00\x00\x00",
				"\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\xFF\xFF\x00\xFF\xFF\xFF\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\xFF\xFF");
			if (Result == 0) {
				reason = 1;
				break;
			}
			else {
				Address = Result;
				Address = RelativeAddressing32(Address + 3);
				qiapiao_2::Memory_Base = Address; //地址
				Address = Result + 0x07;
				qiapiao_2::Memory_BaseOffset = Get32(Address + 3); //偏移

				Address = Result + 0x19;
				qiapiao_2::Memory_2 = Get8(Address + 2); //虚函数

				Address = Result + 0x22;
				qiapiao_2::Memory_3 = Get32(Address + 2); //虚函数

				Address = Result + 0x28;
				qiapiao_2::Memory_4 = Get32(Address + 3); //偏移

				Address = Result + 0x2F;
				qiapiao_2::Memory_5 = Get8(Address + 3); //偏移

				Address = Result + 0x33;
				qiapiao_2::Memory_6 = Get32(Address + 3); //偏移

				Address = Result + 0x3D;
				qiapiao_2::Memory_7 = Get32(Address + 2); //虚函数
			}
			qiapiao_2::Memory_AntiQiapiao = 0x90;
			qiapiao_2::Memory_AntiQiapiao_Enable = 0x90;
		}
*/
		InitHook();
		return 0;
#else
#error 仅支持x86和x64
#endif
		g_TimerID = (UINT_PTR)&Timer_Init;
		SetTimer(QQSpeed::MainWindow, g_TimerID, 1, Timer_Init);//有些操作必须在主线程执行
		return 0;
	} while (false);
	wsprintfW(string,
		XorString(L"未适配当前游戏版本！错误代码：%d,%u\n我们正在为您尝试兼容模式..."),
		reason, time);
	MessageBoxTimeoutW(hWnd, string, XorString(L"卡漂插件"), MB_OK, 0, 5000);
	InitHook();
	return reason;
}
