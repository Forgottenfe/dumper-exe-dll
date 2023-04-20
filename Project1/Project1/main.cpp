#include <iostream>
#include <fstream>
#include <Windows.h>
#include <string>
#include <algorithm>
#include <wininet.h>
#include <tlhelp32.h>
#include <commdlg.h>
#include <Shlobj.h>
#include <Objbase.h>
#include <psapi.h>
#include <PathCch.h>
#include <Shlwapi.h>
#include <vector>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")


#pragma comment(lib, "wininet.lib")

#define _WIN32_WINNT 0x0500
#define TH32CS_SNAPPROCESS 0x00000002
#pragma comment(lib, "Pathcch.lib")

// Функция проверки наличия драйверного инжектора
bool checkDriver() {
	// Получение списка процессов
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnapshot, &pe32)) {
		CloseHandle(hSnapshot);
		return false;
	}

	// Поиск драйверного инжектора
	std::wstring driverName = L"Injector";
	do {
		if (std::wstring(pe32.szExeFile) == driverName) {
			CloseHandle(hSnapshot);
			return true;
		}
	} while (Process32Next(hSnapshot, &pe32));

	CloseHandle(hSnapshot);
	return false;
}

DWORD isDebuggerPresent()
{
	DWORD isDebugger = 0;
	__try {
		__asm {
			mov eax, dword ptr fs : [30h]
			movzx eax, byte ptr[eax + 2h]
			mov isDebugger, eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		isDebugger = 0;
	}
	return isDebugger;
}

void ListProcessModules2(DWORD dwPID)
{
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;

    // Получаем список модулей для процесса
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID);
    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        std::cout << "CreateToolhelp32Snapshot failed" << std::endl;
        return;
    }

    // Устанавливаем размер структуры
    me32.dwSize = sizeof(MODULEENTRY32);

    // Получаем первый модуль
    if (!Module32First(hModuleSnap, &me32))
    {
        std::cout << "Module32First failed" << std::endl;
        CloseHandle(hModuleSnap);
        return;
    }

    // Выводим список модулей
    std::wcout << "DLLs in process (PID: " << dwPID << "):" << std::endl;
    do
    {
        std::wcout << me32.szModule << std::endl;
    } while (Module32Next(hModuleSnap, &me32));

    // Освобождаем ресурсы
    CloseHandle(hModuleSnap);
}

// Функция проверки целостности дампа
bool CheckDumpIntegrity(const std::wstring & dumpName, const std::wstring & moduleName)
{
    // Получаем дескриптор модуля из дампа
    HANDLE hDumpFile = CreateFile(dumpName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDumpFile == INVALID_HANDLE_VALUE) {
        std::cout << "Error opening dump file!" << std::endl;
        return false;
    }
    HMODULE hModule = LoadLibraryEx(moduleName.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES | LOAD_LIBRARY_AS_DATAFILE);
    if (hModule == NULL) {
        std::cout << "Error loading module from dump!" << std::endl;
        CloseHandle(hDumpFile);
        return false;
    }

    // Получаем размер модуля из дампа
    DWORD dwFileSize = GetFileSize(hDumpFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE) {
        std::cout << "Error getting dump file size!" << std::endl;
        FreeLibrary(hModule);
        CloseHandle(hDumpFile);
        return false;
    }

    // Получаем размер модуля из памяти
    HMODULE hModule2 = GetModuleHandle(moduleName.c_str());
    if (hModule2 == NULL) {
        std::cout << "Error getting module handle!" << std::endl;
        FreeLibrary(hModule);
        CloseHandle(hDumpFile);
        return false;
    }
    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule2, &moduleInfo, sizeof(moduleInfo))) {
        std::cout << "Error getting module information!" << std::endl;
        FreeLibrary(hModule);
        CloseHandle(hDumpFile);
        return false;
    }
    DWORD dwModuleSize = moduleInfo.SizeOfImage;

    // Сравниваем размеры модуля
    if (dwFileSize != dwModuleSize) {
        std::cout << "dump file size does not match module size!" << std::endl;
        FreeLibrary(hModule);
        CloseHandle(hDumpFile);
        return false;
    }

    // Сравниваем содержимое модуля
    LPVOID lpModuleBase = (LPVOID)hModule2;
    LPVOID lpDumpBase = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT, PAGE_READWRITE);
    DWORD dwBytesRead;
    if (!ReadFile(hDumpFile, lpDumpBase, dwFileSize, &dwBytesRead, NULL)) {
        std::cout << "Error reading dump file!" << std::endl;
        FreeLibrary(hModule);
        VirtualFree(lpDumpBase, 0, MEM_RELEASE);
        CloseHandle(hDumpFile);
        return false;
    }
    if (memcmp(lpModuleBase, lpDumpBase, dwFileSize) != 0) {
        std::cout << "dump file contents do not match module contents!" << std::endl;
        FreeLibrary(hModule);
        VirtualFree(lpDumpBase, 0, MEM_RELEASE);
        CloseHandle(hDumpFile);
        return false;
    }

    // Освобождаем ресурсы
    FreeLibrary(hModule);
    VirtualFree(lpDumpBase, 0, MEM_RELEASE);
    CloseHandle(hDumpFile);

    return true;
}

// Функция обнаружения зависимостей модуля и создания дампа для всех зависимых модулей
void DumpModuleDependencies(HANDLE hProcess, HMODULE hModule, const std::wstring& dumpFolder)
{
    // Получаем список зависимых модулей
    DWORD dwSize = 0;
    EnumProcessModulesEx(hProcess, NULL, 0, &dwSize, LIST_MODULES_ALL);
    std::vector<HMODULE> hModules(dwSize / sizeof(HMODULE));
    if (EnumProcessModulesEx(hProcess, hModules.data(), dwSize, &dwSize, LIST_MODULES_ALL)) {
        for (HMODULE hDepModule : hModules) {
            // Получаем имя зависимого модуля
            TCHAR szDepModuleName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hDepModule, szDepModuleName, MAX_PATH)) {
                // Создаем дамп зависимого модуля
                std::wstring depModuleName(szDepModuleName);
                std::wstring depDumpName = dumpFolder + L"\\" + depModuleName.substr(depModuleName.find_last_of(L"\\/") + 1) + L".dmp";
                HANDLE hDepDumpFile = CreateFile(depDumpName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (hDepDumpFile != INVALID_HANDLE_VALUE)
                {
                    MODULEINFO moduleInfo;
                    if (GetModuleInformation(hProcess, hDepModule, &moduleInfo, sizeof(moduleInfo))) {
                        DWORD dwBytesWritten;
                        if (!WriteFile(hDepDumpFile, moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage, &dwBytesWritten, NULL)) {
                            std::wcout << L"Error writing dump file for module " << depModuleName << L"!" << std::endl;
                        }
                    }
                    else {
                        std::wcout << L"Error getting module information for module " << depModuleName << L"!" << std::endl;
                    }
                    CloseHandle(hDepDumpFile);
                }
                else {
                    std::wcout << L"Error creating dump file for module " << depModuleName << L"!" << std::endl;
                }
            }
        }
    }
    else {
        std::wcout << L"Error getting module list!" << std::endl;
    }
}


int process2()
{
    // Получаем список процессов
    std::vector<DWORD> aProcesses(1024);
    DWORD cbNeeded;
    if (!EnumProcesses(aProcesses.data(), sizeof(DWORD) * aProcesses.size(), &cbNeeded)) {
        std::cout << "EnumProcesses failed" << std::endl;
        return 1;
    }

    // Вычисляем количество процессов
    DWORD cProcesses = cbNeeded / sizeof(DWORD);

    // Выводим список процессов с их ID
    std::wcout << "Processes:" << std::endl;
    for (unsigned int i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

            // Получаем дескриптор процесса
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);

            // Получаем имя процесса
            if (NULL != hProcess) {
                HMODULE hMod;
                DWORD cbNeeded2;

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded2)) {
                    GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
                }
            }

            // Выводим ID процесса и его имя
            std::wcout << "Processes:id " << aProcesses[i] << " - " << szProcessName << std::endl;

            // Закрываем дескриптор процесса
            CloseHandle(hProcess);
        }
    }

    // Выбираем процесс
    DWORD dwPID;
    std::wcout << "Enter process ID: ";
    std::wcin >> dwPID;

    // Получаем дескриптор процесса
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
    if (hProcess == NULL) {
        std::cout << "Error opening process!" << std::endl;
        return 1;
    }

    // Получаем список модулей выбранного процесса
    DWORD dwSize = 0;
    EnumProcessModulesEx(hProcess, NULL, 0, &dwSize, LIST_MODULES_ALL);
    std::vector<HMODULE> hModules(dwSize / sizeof(HMODULE));
    if (EnumProcessModulesEx(hProcess, hModules.data(), dwSize, &dwSize, LIST_MODULES_ALL)) {
        // Выводим список модулей с их именами
        std::wcout << "Modules:" << std::endl;
        for (HMODULE hModule : hModules) {
            TCHAR szModuleName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hModule, szModuleName, MAX_PATH)) {
                std::wcout << "Modules:" << szModuleName << std::endl;
            }
        }

        // Выбираем модуль для дампа
        std::wstring moduleName;
        std::wcout << "Enter module name: ";
        std::wcin >> moduleName;

        // Получаем дескриптор модуля
        HMODULE hModule = GetModuleHandle(moduleName.c_str());
        if (hModule == NULL)
        {
            std::cout << "Error getting module handle!" << std::endl;
            return 1;
        }

        // Создаем папку для дампов
        std::wstring dumpFolder = L".\\dumps";
        CreateDirectory(dumpFolder.c_str(), NULL);

        // Создаем дамп выбранного модуля
        TCHAR szModuleName[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, hModule, szModuleName, MAX_PATH)) {
            std::wstring moduleDumpName = dumpFolder + L"\\" + std::wstring(szModuleName) + L".dmp";
            HANDLE hModuleDumpFile = CreateFile(moduleDumpName.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hModuleDumpFile != INVALID_HANDLE_VALUE) {
                MODULEINFO moduleInfo;
                if (GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo))) {
                    DWORD dwBytesWritten;
                    if (!WriteFile(hModuleDumpFile, moduleInfo.lpBaseOfDll, moduleInfo.SizeOfImage, &dwBytesWritten, NULL)) {
                        std::cout << "Error writing dump file for module " << szModuleName << "!" << std::endl;
                    }
                }
                else {
                    std::cout << "Error getting module information for module " << szModuleName << "!" << std::endl;
                }
                CloseHandle(hModuleDumpFile);
            }
            else {
                std::cout << "Error creating dump file for module " << szModuleName << "!" << std::endl;
            }

            // Создаем дампы зависимых модулей
            DumpModuleDependencies(hProcess, hModule, dumpFolder);
        }
    }
    else {
        std::cout << "Error getting module list!" << std::endl;
        return 1;
    }

    // Закрываем дескриптор процесса
    CloseHandle(hProcess);

    return 0;
}

void dump_thread() {
    // Проверка наличия драйверного инжектора
    if (checkDriver()) {
        std::cout << "Driver injector detected!" << std::endl;
        return;
    }

    // Проверка на интерпретацию кода
    if (isDebuggerPresent()) {
        std::cout << "Debugger detected!" << std::endl;
        return;
    }

    // Открытие диалогового окна выбора файла или процесса
    OPENFILENAME ofn;
    wchar_t szFileName[MAX_PATH] = L"";
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = szFileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrDefExt = L"exe";

    int choice = 0;
    std::cout << "What do you want to dump? (1 - exe, coder by Forgotten 2 - process): ";
    std::cin >> choice;

    if (choice == 1) {
        if (GetOpenFileName(&ofn) == TRUE) {
            // Открытие файла и создание его дампа
            std::ifstream file(ofn.lpstrFile, std::ios::binary);
            if (!file) {
                std::cout << "Error opening file!" << std::endl;
                return;
            }
            std::wstring fileName = ofn.lpstrFile;
            std::wstring::size_type pos = fileName.find_last_of(L"\\/");
            std::wstring path = fileName.substr(0, pos);
            std::wstring name = fileName.substr(pos + 1);
            std::wstring ext = name.substr(name.find_last_of(L".") + 1);
            std::wstring dumpName = name.substr(0, name.find_last_of(L".")) + L"_dump." + ext;
            std::wstring dumpPath = path + L"\\" + dumpName;
            std::ifstream dumpFile(dumpPath, std::ios::binary);
            if (dumpFile) {
                std::cout << "dump file already exists!" << std::endl;
                return;
            }
            std::ofstream dump(dumpPath, std::ios::binary);
            dump << file.rdbuf();
            file.close();
            dump.close();
            std::cout << "dump created successfully!" << std::endl;
        }
    }
    else if (choice == 2) {
        process2();
    }
    else {
        std::cout << "Invalid choice!" << std::endl;
        return;
    }

    // Получение пути к дампу
    std::wstring dumpPath = L"";

    // Проверка наличия файла дампа
    if (dumpPath.empty()) {
        std::cout << "dump file not selected!" << std::endl;
        return;
    }

    // Получение информации о файле
    WIN32_FIND_DATA fileInfo;
    HANDLE hFile = FindFirstFile(dumpPath.c_str(), &fileInfo);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cout << "File not found!" << std::endl;
        return;
    }
}


void DumpMemoryToFile(const char* filename, LPVOID lpAddress, SIZE_T dwSize)
{
	HANDLE hFile = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwBytesWritten;
		if (WriteFile(hFile, lpAddress, dwSize, &dwBytesWritten, NULL))
		{
			std::cout << "Memory dump saved to " << filename << std::endl;
		}
		else
		{
			std::cerr << "Failed to write memory dump to file." << std::endl;
		}
		CloseHandle(hFile);
	}
	else
	{
		std::cerr << "Failed to create file " << filename << std::endl;
	}
}

int main2(int argc, char** argv)
{
	// Check for correct usage
	if (argc != 2)
	{
		std::cerr << "Usage: " << argv[0] << " <process name>" << std::endl;
		return 1;
	}

	// Get process handle and module handle
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	HMODULE hModule = GetModuleHandleA(argv[1]);

	// Get module information
	MODULEINFO moduleInfo = { 0 };
	GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(MODULEINFO));

	// Get the path of the executable file
	char exePath[MAX_PATH];
	GetModuleFileNameA(NULL, exePath, MAX_PATH);


	// Close the process handle
	CloseHandle(hProcess);

	return 0;
}

int main() {
	// Эмуляция отладчика
	DWORD dwOldProtect;
	VirtualProtect((LPVOID)&IsDebuggerPresent, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*(BYTE*)&IsDebuggerPresent = 0xC3;
	VirtualProtect((LPVOID)&IsDebuggerPresent, 1, dwOldProtect, &dwOldProtect);

	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&dump_thread, NULL, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	// Восстановление отладчика
	VirtualProtect((LPVOID)&IsDebuggerPresent, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*(BYTE*)&IsDebuggerPresent = 0x00;
	VirtualProtect((LPVOID)&IsDebuggerPresent, 1, dwOldProtect, &dwOldProtect);

	return 0;
}