//Includes
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <psapi.h>
#include <stdint.h>

//Offsets
#define dwLocalPlayerPawn 0x187CEF0
#define dwEntityList 0x1A292F0
#define m_iTeamNum 0x3E3 // Offset for uint8
#define m_iHealth 0x344
#define m_iIDEntIndex 0x1458 // CEntityIndex
#define m_fFlags 0x3EC // uint32

//Delays
#define TRIGGER_MIN_DELAY 10
#define TRIGGER_MAX_DELAY 15
#define AFTERTRIGGER_MIN_DELAY 1
#define AFTERTRIGGER_MAX_DELAY 10

#define BHOP_MAX_DELAY 5


//Constants
#define stand 65665
#define crouch 65667

//Global variables
// Read the team number of the local player
uintptr_t localTeamAddress;
unsigned int localTeamNum = 0; // 1 byte for team number
uintptr_t entityIndexAddress;
uintptr_t entityIndex = 0; // Assuming entity index is a pointer-sized value
BOOL FFA = FALSE;
BOOL BHOP = FALSE;
BOOL TRIGGER = FALSE;

//Modules
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("Failed to open process token (Error: %lu)\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        printf("Failed to lookup privilege value (Error: %lu)\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("Failed to adjust token privileges (Error: %lu)\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("The token does not have the specified privilege.\n");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

DWORD GetProcessIdByName(const char *processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (strcmp(pe.szExeFile, processName) == 0) {
                processId = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return processId;
}

LPVOID GetModuleBaseAddress(DWORD processId, const char *moduleName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);

    LPVOID baseAddress = NULL;
    if (Module32First(hSnapshot, &me)) {
        do {
            if (strcmp(me.szModule, moduleName) == 0) {
                baseAddress = me.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnapshot, &me));
    }

    CloseHandle(hSnapshot);
    return baseAddress;
}

void ReadMemoryInLoop(DWORD processId, LPVOID baseAddress, SIZE_T size) {
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        printf("Failed to open process (Error: %lu)\n", GetLastError());
        return;
    }

    if (!EnableDebugPrivilege()) {
        printf("Failed to enable debug privilege\n");
        CloseHandle(hProcess);
        return;
    }

    BYTE *buffer = (BYTE *)malloc(size);
    if (buffer == NULL) {
        printf("Memory allocation failed\n");
        CloseHandle(hProcess);
        return;
    }

    while (1) {
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, baseAddress, buffer, size, &bytesRead)) {
            printf("Read %zu bytes from address %p:\n", bytesRead, baseAddress);
            for (SIZE_T i = 0; i < bytesRead; i++) {
                printf("%02X ", buffer[i]);
                if ((i + 1) % 16 == 0) printf("\n");
            }
            printf("\n");
        } else {
            printf("Failed to read process memory (Error: %lu)\n", GetLastError());
            break;
        }

        Sleep(1); // Pause for 1 second before reading again
    }

    free(buffer);
    CloseHandle(hProcess);
}

void leftClick(int delay) 
{
    Sleep(delay);
        // Simulate a left mouse click
    INPUT input = {0};
    input.type = INPUT_MOUSE;
    input.mi.dwFlags = MOUSEEVENTF_LEFTDOWN; // Press left mouse button

    // Send the mouse down event
    SendInput(1, &input, sizeof(INPUT));

    // Set up the mouse up event
    input.mi.dwFlags = MOUSEEVENTF_LEFTUP; // Release left mouse button

    // Send the mouse up event
    SendInput(1, &input, sizeof(INPUT));

    // printf("[DEBUG] - Simulated left mouse click %d\n", __LINE__);
}

void pressSpacebar(int delay) 
{
    Sleep(delay); // Wait for the specified delay

    // Create an INPUT structure for the key press
    INPUT input = {0};
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = VK_SPACE; // Virtual key code for spacebar
    input.ki.dwFlags = 0; // Key down event

    // Send the key down event (press spacebar)
    SendInput(1, &input, sizeof(INPUT));

    // Set up the key release event
    input.ki.dwFlags = KEYEVENTF_KEYUP; // Key up event

    // Send the key up event (release spacebar)
    SendInput(1, &input, sizeof(INPUT));

    // printf("[DEBUG] - Simulated spacebar press %d\n", __LINE__);
}

int main() {
    const char *processName = "cs2.exe";
    const char *moduleName = "client.dll";
    DWORD processId;
    
    while (1)
    {
        processId = GetProcessIdByName(processName);

        if (processId == 0) {
            printf("Process %s not found\n", processName);
            Sleep(5000);
            continue;
        }
        if (processId != 0) 
        {
            printf("Process %s found with PID: %lu\n", processName, processId);
            break;
        }
    }
    
    LPVOID moduleBaseAddress;
    while (1)
    {
        moduleBaseAddress = GetModuleBaseAddress(processId, moduleName);
        if (moduleBaseAddress == NULL) {
                printf("Module %s not found in process %s\n", moduleName, processName);
                Sleep(5000);
                continue;
            }
        else 
        {
            printf("Module %s found at base address: %p\n", moduleName, moduleBaseAddress);
            break;
        }
        
    }
    
    // Calculate the target address (client.dll base + dwLocalPlayerPawn)
    LPVOID targetAddress = (LPVOID)((uintptr_t)moduleBaseAddress + dwLocalPlayerPawn);
    printf("Target address (client.dll + dwLocalPlayerPawn): %p\n", targetAddress);

    // Read memory at target address
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        printf("Failed to open process (Error: %lu)\n", GetLastError());
        return 1;
    }

    if (!EnableDebugPrivilege()) {
        printf("Failed to enable debug privilege\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Read 4 bytes (assuming the value at dwLocalPlayerPawn is a pointer or similar)
    DWORD localPlayerAddress = 0;
    LPVOID entityListAddress = (LPVOID)((uintptr_t)moduleBaseAddress + dwEntityList);
    DWORD entityListValue = 0;

    SIZE_T bytesRead;
    while(1)
    {

        if (ReadProcessMemory(hProcess, targetAddress, &localPlayerAddress, sizeof(localPlayerAddress), &bytesRead)) {
            printf("Read %zu bytes from address %p:\n", bytesRead, targetAddress);
            printf("Local Player Address: 0x%08X\n", localPlayerAddress);
            if (localPlayerAddress != 0x00000000) 
            {
                break;
            }
            else 
            {
                Sleep(5000);
                continue;
            }
        } else {
            printf("Failed to read process memory (Error: %lu)\n", GetLastError());
            Sleep(5000);
            continue;
        }
    }
   
    // Read dwEntityList
    if (ReadProcessMemory(hProcess, entityListAddress, &entityListValue, sizeof(entityListValue), &bytesRead)) {
        printf("Read %zu bytes from target address %p (dwEntityList): 0x%08X\n", bytesRead, entityListAddress, entityListValue);
    } else {
        printf("Failed to read from dwEntityList (Error: %lu)\n", GetLastError());
    }

    while(1)
    {

        //Hotkeys
        // Exit if the 'Esc' key (virtual-key code VK_ESCAPE) is pressed
        if (GetAsyncKeyState(VK_END) & 0x8000) {
            printf("Exiting...\n");
            break;
        }
        // Toggle FFA mode when Page Up (VK_PRIOR) is pressed
        if (GetAsyncKeyState(VK_NEXT) & 0x8000) {
            FFA = !FFA; // Toggle TRUE/FALSE
            printf("FFA mode %s\n", FFA ? "ON" : "OFF");

            // Sleep to prevent multiple triggers
            Sleep(200);
        }
        // Toggle BHOP when Insert (VK_INSERT) is pressed
        if (GetAsyncKeyState(VK_INSERT) & 0x8000) {
            BHOP = !BHOP;
            printf("BHOP mode %s\n", BHOP ? "ON" : "OFF");
            Sleep(200);
        }

        // Toggle TRIGGER when Delete (VK_DELETE) is pressed
        if (GetAsyncKeyState(VK_DELETE) & 0x8000) {
            TRIGGER = !TRIGGER;
            printf("TRIGGER mode %s\n", TRIGGER ? "ON" : "OFF");
            Sleep(200);
        }

        if (GetAsyncKeyState(VK_PRIOR) & 0x8000) { // If Page Up is pressed
            printf("PAGE UP pressed: Reloading module base address...\n");
            moduleBaseAddress = GetModuleBaseAddress(processId, moduleName); // Reload module base address
            if (moduleBaseAddress == NULL) {
                printf("Module %s not found, retrying...\n", moduleName);
            } else {
                targetAddress = (LPVOID)((uintptr_t)moduleBaseAddress + dwLocalPlayerPawn); // Recalculate target address
                printf("New target address: %p\n", targetAddress);

                // Attempt to read memory from the recalculated address
                DWORD localPlayerAddress = 0;
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, targetAddress, &localPlayerAddress, sizeof(localPlayerAddress), &bytesRead)) {
                    printf("Read %zu bytes from new target address %p:\n", bytesRead, targetAddress);
                    printf("Local Player Address: 0x%08X\n", localPlayerAddress);
                } else {
                    printf("Failed to read from new target address (Error: %lu)\n", GetLastError());
                }

                // Read dwEntityList
                if (ReadProcessMemory(hProcess, entityListAddress, &entityListValue, sizeof(entityListValue), &bytesRead)) {
                    printf("Read %zu bytes from target address %p (dwEntityList): 0x%08X\n", bytesRead, entityListAddress, entityListValue);
                } else {
                    printf("Failed to read from dwEntityList (Error: %lu)\n", GetLastError());
                }
             

            }
            Sleep(1); // Add a short delay to prevent repeated triggering
        }

        uintptr_t localPlayerAddress = 0; // Reset the variable to store the new address
        SIZE_T bytesRead;
                    // Step 1: Read the Local Player Address
            if (ReadProcessMemory(hProcess, targetAddress, &localPlayerAddress, sizeof(localPlayerAddress), &bytesRead)) {
                // printf("Read %zu bytes from target address %p:\n", bytesRead, targetAddress);
                // printf("Local Player Address: 0x%016llX\n", localPlayerAddress);
                }
        //TriggerBot func
        if (TRIGGER && GetAsyncKeyState(VK_XBUTTON2) & 0x8000)
        {
            // Read the team number of the local player
                uintptr_t localTeamAddress = localPlayerAddress + m_iTeamNum; // Calculate address
                int localTeamNum = 0; // Store result as int

                if (ReadProcessMemory(hProcess, (LPCVOID)localTeamAddress, &localTeamNum, sizeof(localTeamNum), &bytesRead)) 
                {
                    // printf("Local Player Team Number: %d\n", localTeamNum);
                } 
                else 
                {
                    printf("Failed to read Local Player Team Number (Error: %lu)\n", GetLastError());
                }

                // Step 3: Read mEntIndex as an integer
                uintptr_t entityIndexAddress = localPlayerAddress + m_iIDEntIndex; // Calculate address
                int entityIndex = 0; // Store result as int

                if (ReadProcessMemory(hProcess, (LPCVOID)entityIndexAddress, &entityIndex, sizeof(entityIndex), &bytesRead)) {
                    // printf("Local Player Entity Index: %d\n", entityIndex);
                    if (entityIndex != -1)
                    {
                    

                        uintptr_t entityListBase;
                        ReadProcessMemory(hProcess, (LPCVOID)(moduleBaseAddress + dwEntityList), &entityListBase, sizeof(entityListBase), &bytesRead);
                        uintptr_t entityEntry;
                        ReadProcessMemory(hProcess, (LPCVOID)(entityListBase + 0x8 * ((entityIndex >> 9) & 0x7F) + 0x10), &entityEntry, sizeof(entityEntry), &bytesRead);

                        uintptr_t entityPointer;
                        ReadProcessMemory(hProcess, (LPCVOID)(entityEntry + 0x78 * (entityIndex & 0x1FF)), &entityPointer, sizeof(entityPointer), &bytesRead);



                        int entHealth, entTeam;

                        // Read Team Number
                        ReadProcessMemory(hProcess, (LPCVOID)(entityPointer + m_iTeamNum), &entTeam, sizeof(entTeam), &bytesRead);

                        // Read Health
                        ReadProcessMemory(hProcess, (LPCVOID)(entityPointer + m_iHealth), &entHealth, sizeof(entHealth), &bytesRead);

                        // printf("TEAM: %d HP: %d\n", entTeam, entHealth);
                        if (!FFA && localTeamNum != entTeam || FFA && (entTeam == 2 || entTeam == 3))
                        {
                            int fireDelay = rand() % TRIGGER_MAX_DELAY + TRIGGER_MIN_DELAY; // Random delay between 10-25 ms
                            int afterfireDelay = rand() % AFTERTRIGGER_MAX_DELAY + AFTERTRIGGER_MIN_DELAY; // Random delay between 10-25 ms
                            Sleep(fireDelay);
                            leftClick(0);
                            Sleep(afterfireDelay);
                        }
                    }
                }
                else 
                {
                    printf("Failed to read Local Player Entity Index (Error: %lu)\n", GetLastError());
                }
        }

        //Bhop
        if (BHOP && GetAsyncKeyState(VK_XBUTTON1) & 0x8000)
        {
            // Read fFlags
            uint32_t fFlag;
            if (ReadProcessMemory(hProcess,(LPVOID) (localPlayerAddress + m_fFlags), &fFlag, sizeof(fFlag), &bytesRead)) {
                // printf("Read %zu bytes from target address %p (m_fFlags): %d\n", bytesRead, localPlayerAddress + m_fFlags, fFlag);
            } else {
                printf("[DEBUG] - Failed to read from m_fFlags (Error: %lu)\n", GetLastError());
            }

            if (fFlag == stand || fFlag == crouch)
            {
                int preDelay = rand() % BHOP_MAX_DELAY + 1;  // Random delay between 1 and 10 ms
                int postDelay = rand() % (BHOP_MAX_DELAY + 1 - preDelay) + 1;  // Ensure total stays within 15 ms

                Sleep(preDelay);
                pressSpacebar(0);
                Sleep(postDelay);
            }
        }
        Sleep(1);
    }
    CloseHandle(hProcess);
    return 0;
}
