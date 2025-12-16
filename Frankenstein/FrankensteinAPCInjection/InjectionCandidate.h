#include <Windows.h>

struct InjectionCandidate {
	DWORD processId;
	DWORD threadId;
	LPVOID rwxAddress;
	HANDLE hThread;
	HANDLE hProcess;
};