#pragma once

#include <windows.h>
#include <vector>
#include <fstream>
#include <map>

struct _PE_FILE;

typedef struct _PE_DEPENDECY
{
	CHAR Name[ MAX_PATH ];
	_PE_FILE* File;

} PE_DEPENDENCY, * PPE_DEPENDENCY;

typedef struct _PE_FILE
{
	CHAR FilePath[ MAX_PATH ];
	LPSTR FileName;
	
	std::vector< BYTE > FileData;

	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeaders;

	_PE_FILE* Parent;

	std::vector< PE_DEPENDENCY > Dependencies;

} PE_FILE, * PPE_FILE;

#define PAGE_SHIFT      12
#define PAGE_SIZE       (1UL << PAGE_SHIFT)
#define PAGE_MASK       (~(PAGE_SIZE-1))

#define PAGE_ALIGN(addr)        (((addr)+PAGE_SIZE-1)&PAGE_MASK)

BOOL
PeOpenFile(
	_In_    LPCSTR Path,
	_Inout_ PPE_FILE PEFile
);

BOOL
PeIsDependencyWalked(
	_In_ LPCSTR FileName,
	_In_ PPE_FILE PEFile,
	_Inout_ PPE_FILE* Dependency
);

BOOL
PeWalkFileDependencies(
	_Inout_ PPE_FILE PEFile,
	_In_ LONG Depth
);

BOOL
PeCloseFile(
	_Inout_ PPE_FILE PEFile
);