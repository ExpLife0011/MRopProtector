/*
=========================================================================

    MRopProtector:
    User-mode implementation of PsValidateUserStack() of Windows 8 kernel,
	for protecting programs against ROP attacks.
    
	Developed by:

    Shahriyar Jalayeri, Iran Honeynet Chapter
    Shahriyar.j <at > gmail <dot> com
    http://www.irhoneynet.org/

=========================================================================
*/

#include "stdafx.h"
#include <Windows.h>
#include "detours.h"
#pragma comment(lib,"detours.lib")
#pragma comment(lib,"detoured.lib")

//#define MSGREPORT

static LPVOID (WINAPI *VirtualAlloc_    )(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAlloc;
static LPVOID (WINAPI *VirtualAllocEx_  )(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAllocEx;
static   BOOL (WINAPI *VirtualProtect_  )(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, PDWORD flProtect) = VirtualProtect;
static   BOOL (WINAPI *VirtualProtectEx_)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, PDWORD flProtect) = VirtualProtectEx;
static LPVOID (WINAPI *MapViewOfFile_   )(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap) = MapViewOfFile;
static LPVOID (WINAPI *MapViewOfFileEx_ )(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap, LPVOID lpBaseAddress) = MapViewOfFileEx;

BOOL bStackProtectionChange = FALSE;

LPVOID WINAPI 
	VirtualAllocRopProtect(LPVOID lpAddress, 
	                       SIZE_T dwSize, 
						   DWORD flAllocationType, 
						   DWORD flProtect)
{
	NT_TIB * ThreadInfo;
	HANDLE hCurrentThread;
	CONTEXT * cThreadContext = (CONTEXT *)LocalAlloc(LMEM_ZEROINIT, sizeof(CONTEXT));

	hCurrentThread = GetCurrentThread();
	cThreadContext->ContextFlags = CONTEXT_CONTROL;
	// get the thread stack range from TIB.
	ThreadInfo = (NT_TIB *) __readfsdword( 0x18 );
	if ( GetThreadContext( hCurrentThread, cThreadContext ) )
	{
		// check if thread is passing the acual stack boundaries.
		if ( cThreadContext->Esp < (DWORD)ThreadInfo->StackLimit || cThreadContext->Esp >= (DWORD)ThreadInfo->StackBase ) 
		{
			// at this point everything is definitely messed up, so no matter what we do with stack.
			__asm
				{
					mov esp, fs:[0x8] 
					add esp,400h 
				}
			// rise the bar :D
			RaiseException( STATUS_STACK_BUFFER_OVERRUN, EXCEPTION_NONCONTINUABLE, 0, NULL);
		}
	}

	return (VirtualAlloc_(lpAddress, dwSize, flAllocationType, flProtect));
}


LPVOID WINAPI
	VirtualAllocExRopProtect(HANDLE hProcess, 
	                         LPVOID lpAddress, 
						 	 SIZE_T dwSize, 
							 DWORD flAllocationType, 
							 DWORD flProtect)
{
	NT_TIB * ThreadInfo;
	HANDLE hCurrentThread;
	CONTEXT * cThreadContext = (CONTEXT *)LocalAlloc(LMEM_ZEROINIT, sizeof(CONTEXT));

	hCurrentThread = GetCurrentThread();
	cThreadContext->ContextFlags = CONTEXT_CONTROL;
	ThreadInfo = (NT_TIB *) __readfsdword( 0x18 );
	if ( GetThreadContext( hCurrentThread, cThreadContext ) )
	{
		if ( cThreadContext->Esp < (DWORD)ThreadInfo->StackLimit || cThreadContext->Esp >= (DWORD)ThreadInfo->StackBase ) 
		{
			__asm
				{
					mov esp, fs:[0x8] 
					add esp,400h 
				}
			RaiseException( STATUS_STACK_BUFFER_OVERRUN, EXCEPTION_NONCONTINUABLE, 0, NULL);
		}
	}
	
	return (VirtualAllocEx_(hProcess, lpAddress, dwSize, flAllocationType, flProtect));
}


BOOL WINAPI
	VirtualProtectRopProtect(LPVOID lpAddress, 
	                         SIZE_T dwSize, 
							 DWORD flAllocationType, 
							 PDWORD flProtect)
{

	PNT_TIB ThreadInfo;
	PCONTEXT cThreadContext = (PCONTEXT)LocalAlloc(LMEM_ZEROINIT, sizeof(CONTEXT));
	cThreadContext->ContextFlags = CONTEXT_CONTROL;
	ThreadInfo = (PNT_TIB) __readfsdword( 0x18 );
	if ( GetThreadContext( (HANDLE)0xFFFFFFFE, cThreadContext ) )
	{
		if ( cThreadContext->Esp < (DWORD)ThreadInfo->StackLimit || cThreadContext->Esp >= (DWORD)ThreadInfo->StackBase ) 
		{
			__asm
				{
					mov esp, fs:[0x8] 
					add esp,400h 
				}
			RaiseException( STATUS_STACK_BUFFER_OVERRUN, EXCEPTION_NONCONTINUABLE, 0, NULL);

		} else if ( bStackProtectionChange )
		{
			if ( lpAddress > ThreadInfo->StackLimit || lpAddress <= ThreadInfo->StackBase )
			{
				RaiseException( STATUS_STACK_BUFFER_OVERRUN, EXCEPTION_NONCONTINUABLE, 0, NULL);
			}
		}
	}
	
	return (VirtualProtect_( lpAddress, dwSize, flAllocationType, flProtect));
}


BOOL WINAPI
	VirtualProtectExRopProtect(HANDLE hProcess, 
	                           LPVOID lpAddress, 
							   SIZE_T dwSize, 
							   DWORD flAllocationType, 
							   PDWORD flProtect)
{

	NT_TIB * ThreadInfo;
	HANDLE hCurrentThread;
	CONTEXT * cThreadContext = (CONTEXT *)LocalAlloc(LMEM_ZEROINIT, sizeof(CONTEXT));

	hCurrentThread = GetCurrentThread();
	cThreadContext->ContextFlags = CONTEXT_CONTROL;
	ThreadInfo = (NT_TIB *) __readfsdword( 0x18 );
	if ( GetThreadContext( hCurrentThread, cThreadContext ) )
	{
		if ( cThreadContext->Esp < (DWORD)ThreadInfo->StackLimit || cThreadContext->Esp >= (DWORD)ThreadInfo->StackBase ) 
		{
			__asm
				{
					mov esp, fs:[0x8] 
					add esp,400h 
				}
			RaiseException( STATUS_STACK_BUFFER_OVERRUN, EXCEPTION_NONCONTINUABLE, 0, NULL);
		} else if ( bStackProtectionChange )
		{
			if ( lpAddress > ThreadInfo->StackLimit || lpAddress <= ThreadInfo->StackBase )
			{
				RaiseException( STATUS_STACK_BUFFER_OVERRUN, EXCEPTION_NONCONTINUABLE, 0, NULL);
			}
		}
	}

	return (VirtualProtectEx_(hProcess, lpAddress, dwSize, flAllocationType, flProtect));
}


LPVOID WINAPI 
	MapViewOfFileRopProtect(HANDLE hFileMappingObject, 
	                        DWORD dwDesiredAccess, 
							DWORD dwFileOffsetHigh, 
							DWORD dwFileOffsetLow, 
							SIZE_T dwNumberOfBytesToMap)
{

	NT_TIB * ThreadInfo;
	HANDLE hCurrentThread;
	CONTEXT * cThreadContext = (CONTEXT *)LocalAlloc(LMEM_ZEROINIT, sizeof(CONTEXT));

	hCurrentThread = GetCurrentThread();
	cThreadContext->ContextFlags = CONTEXT_CONTROL;
	ThreadInfo = (NT_TIB *) __readfsdword( 0x18 );
	if ( GetThreadContext( hCurrentThread, cThreadContext ) )
	{
		if ( cThreadContext->Esp < (DWORD)ThreadInfo->StackLimit || cThreadContext->Esp >= (DWORD)ThreadInfo->StackBase ) 
		{
			__asm
				{
					mov esp, fs:[0x8] 
					add esp,400h 
				}
			RaiseException( STATUS_STACK_BUFFER_OVERRUN, EXCEPTION_NONCONTINUABLE, 0, NULL);
		}
	}

	return (MapViewOfFile_(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap));
}

LPVOID WINAPI 
	MapViewOfFileExRopProtect(HANDLE hFileMappingObject, 
	                          DWORD dwDesiredAccess, 
							  DWORD dwFileOffsetHigh, 
							  DWORD dwFileOffsetLow, 
							  SIZE_T dwNumberOfBytesToMap,
							  LPVOID lpBaseAddress)
{

	NT_TIB * ThreadInfo;
	HANDLE hCurrentThread;
	CONTEXT * cThreadContext = (CONTEXT *)LocalAlloc(LMEM_ZEROINIT, sizeof(CONTEXT));

	hCurrentThread = GetCurrentThread();
	cThreadContext->ContextFlags = CONTEXT_CONTROL;
	ThreadInfo = (NT_TIB *) __readfsdword( 0x18 );
	if ( GetThreadContext( hCurrentThread, cThreadContext ) )
	{
		if ( cThreadContext->Esp < (DWORD)ThreadInfo->StackLimit || cThreadContext->Esp >= (DWORD)ThreadInfo->StackBase ) 
		{
			__asm
				{
					mov esp, fs:[0x8] 
					add esp,400h 
				}
			RaiseException( STATUS_STACK_BUFFER_OVERRUN, EXCEPTION_NONCONTINUABLE, 0, NULL);
		}
	}

	return (MapViewOfFileEx_(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap, lpBaseAddress));
}


VOID
	InstallProtection()
{

	LONG error;

    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

	// hooking functions
	DetourAttach(&(PVOID&)VirtualAlloc_    , VirtualAllocRopProtect);
	DetourAttach(&(PVOID&)VirtualAllocEx_  , VirtualAllocExRopProtect);
	DetourAttach(&(PVOID&)VirtualProtect_  , VirtualProtectRopProtect);
	DetourAttach(&(PVOID&)VirtualProtectEx_, VirtualProtectExRopProtect);
	DetourAttach(&(PVOID&)MapViewOfFile_   , MapViewOfFileRopProtect);
	DetourAttach(&(PVOID&)MapViewOfFileEx_ , MapViewOfFileExRopProtect);
    error = DetourTransactionCommit();

    if (error == NO_ERROR) {
#ifdef MSGREPORT
        MessageBox(NULL,"Rop Detector Started.",NULL, MB_OK);
#endif
    }
    else {
#ifdef MSGREPORT
        MessageBox(NULL,"Rop Detector.",NULL, MB_OK);
#endif
    }
}

VOID
	Uninstall()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	// unhooking functions
	DetourDetach(&(PVOID&)VirtualAlloc_    , VirtualAllocRopProtect);
	DetourDetach(&(PVOID&)VirtualAllocEx_  , VirtualAllocExRopProtect);
	DetourDetach(&(PVOID&)VirtualProtect_  , VirtualProtectRopProtect);
	DetourDetach(&(PVOID&)VirtualProtectEx_, VirtualProtectExRopProtect);
	DetourDetach(&(PVOID&)MapViewOfFile_   , MapViewOfFileRopProtect);
	DetourDetach(&(PVOID&)MapViewOfFileEx_ , MapViewOfFileExRopProtect);

	DetourTransactionCommit();
}


