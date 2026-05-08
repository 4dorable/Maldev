#include <stdio.h>
#include <Windows.h>

int main(int argc, char **argv) 
{
	if (argc < 2)
	{
		printf("[!] Il faut indiquer la DLL\n");
		return -1;
	}

	printf("[#] Injection de %s\n", argv[1]);

	HANDLE hModule = LoadLibraryA(argv[1]);
	if (!hModule)
	{
		printf("[!] Load Library Failed : %lu\n", GetLastError());
		return -1;
	}

	printf("[#] Library Loadee !\n");
	getchar();

	return 0;
}