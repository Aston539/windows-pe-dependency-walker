#include "pefile.h"

BOOL
PeOpenFile(
	_In_    LPCSTR Path,
	_Inout_ PPE_FILE PEFile
)
{
	if ( PEFile->FilePath[ NULL ] == NULL )
	{
		strcpy_s( PEFile->FilePath, Path );
	}
	
	if ( PEFile->FileName == NULL )
	{
		PEFile->FileName = ( LPSTR )strstr( PEFile->FilePath, "\\" );

		while ( ( LPSTR )strstr( PEFile->FileName + 1, "\\" ) )
		{
			PEFile->FileName = ( LPSTR )strstr( PEFile->FileName + 1, "\\" );
		}

		PEFile->FileName++;
	}

	//
	// attempt to open a handle to
	// the target pe file
	//
	std::fstream FileStream( Path, std::fstream::binary | std::fstream::in );

	if ( FileStream.is_open( ) )
	{
		//
		// set file cursor to the end
		//
		FileStream.seekg( NULL, std::fstream::end );

		//
		// get offset of file cursor
		// i.e. the size of the file
		//
		PEFile->FileData.resize( FileStream.tellg( ) );

		//
		// reset file cursor to the beginning
		//
		FileStream.seekg( NULL, std::fstream::beg );

		//
		// read in the file
		//
		if ( !FileStream.read( ( PCHAR )PEFile->FileData.data( ), PEFile->FileData.size( ) ) )
		{
			return FALSE;
		}

		//
		// get addresses of pe headers inside our data
		//
		PEFile->DosHeader = ( PIMAGE_DOS_HEADER )( PEFile->FileData.data( ) );
		PEFile->NtHeaders = ( PIMAGE_NT_HEADERS )( ( UINT_PTR )PEFile->DosHeader + PEFile->DosHeader->e_lfanew );

		//
		// get section headers
		//
		PIMAGE_SECTION_HEADER SectionHead = IMAGE_FIRST_SECTION( PEFile->NtHeaders );
		PIMAGE_SECTION_HEADER LastSectionHead = &SectionHead[ PEFile->NtHeaders->FileHeader.NumberOfSections - 1 ];

		//
		// allocate a new file data just while
		// we align it, make sure to allocate
		// the size of the total file in memory
		//
		std::vector< BYTE > FileDataCopy( PEFile->NtHeaders->OptionalHeader.SizeOfImage );

		//
		// copy pe headers over
		// 
		//
		memcpy( FileDataCopy.data( ), PEFile->FileData.data( ), PEFile->NtHeaders->OptionalHeader.SizeOfHeaders );

		//
		// align file so that we dont have to
		// resolve file offsets
		//
		for ( ULONG I = 0; I < PEFile->NtHeaders->FileHeader.NumberOfSections; I++ )
		{
			PIMAGE_SECTION_HEADER CurrentSection = &SectionHead[ I ];

			//
			// copy data from file data at non aligned address
			// to file data copy at the aligned address
			//
			memcpy( FileDataCopy.data( ) + CurrentSection->VirtualAddress, PEFile->FileData.data( ) + CurrentSection->PointerToRawData, CurrentSection->SizeOfRawData );
		}

		//
		// clear current file data
		//
		PEFile->FileData.clear( );

		//
		// re construct file data as
		// aligned file data
		//
		PEFile->FileData.resize( FileDataCopy.size( ) );

		memcpy( PEFile->FileData.data( ), FileDataCopy.data( ), PEFile->FileData.size( ) );
	}
	else
	{
		//
		// this is likely a windows dependency
		// 
		//  this api will load it into memory 
		//  aligned for us but will not resolve
		//  and dependencies or call its entry point
		//
		HMODULE LibHandle = LoadLibraryExA( Path, NULL, DONT_RESOLVE_DLL_REFERENCES );

		if ( !LibHandle )
		{
			return FALSE;
		}

		PIMAGE_DOS_HEADER DosHeader = ( PIMAGE_DOS_HEADER )( LibHandle );
		PIMAGE_NT_HEADERS NtHeaders = ( PIMAGE_NT_HEADERS )( ( UINT_PTR )LibHandle + DosHeader->e_lfanew );

		PEFile->FileData.resize( NtHeaders->OptionalHeader.SizeOfImage );

		memcpy( PEFile->FileData.data( ), ( PVOID )LibHandle, PEFile->FileData.size( ) );

		FreeLibrary( LibHandle );
	}

	//
	// fix addresses of headers incase
	// they changed during copy and resize
	// operations
	//
	PEFile->DosHeader = ( PIMAGE_DOS_HEADER )( PEFile->FileData.data( ) );
	PEFile->NtHeaders = ( PIMAGE_NT_HEADERS )( ( UINT_PTR )PEFile->DosHeader + PEFile->DosHeader->e_lfanew );

	return TRUE;
}

BOOL
PeIsDependencyWalked(
	_In_ LPCSTR FileName,
	_In_ PPE_FILE PEFile,
	_Inout_ PPE_FILE* Dependency
)
{
	if ( !Dependency )
	{
		return FALSE;
	}

	if ( PEFile->Parent && _stricmp( PEFile->Parent->FileName, FileName ) == NULL )
	{
		*Dependency = PEFile->Parent;

		return TRUE;
	}

	for ( auto& Dep : PEFile->Dependencies )
	{
		if ( _stricmp( Dep.File->FileName, FileName ) == NULL )
		{
			*Dependency = Dep.File;

			return TRUE;
		}
	}

	return FALSE;
}

BOOL
PeWalkFileDependencies(
	_Inout_ PPE_FILE PEFile,
	_In_ LONG Depth
)
{
	UINT_PTR Base = ( UINT_PTR )PEFile->FileData.data( );

	PIMAGE_DATA_DIRECTORY ImportDirectory = &PEFile->NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];

	if ( !ImportDirectory->Size || !ImportDirectory->VirtualAddress )
	{
		//
		// this file does not have any imports
		//
		return TRUE;
	}

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = ( PIMAGE_IMPORT_DESCRIPTOR )( Base + ImportDirectory->VirtualAddress );

	if ( !ImportDescriptor->Name )
	{
		//
		// invalid initial import descriptor
		//
		return FALSE;
	}

	for ( PIMAGE_IMPORT_DESCRIPTOR  CurrentDescriptor = ImportDescriptor;
									CurrentDescriptor->Name;
									CurrentDescriptor++ )
	{
		LPCSTR FileName = ( LPCSTR )( Base + CurrentDescriptor->Name );

		PPE_FILE DepPEFile = NULL;
		BOOL WasWalked = PeIsDependencyWalked( FileName, PEFile, &DepPEFile );
		
		if ( WasWalked == FALSE || !DepPEFile )
		{
			//
			// use new so std::vector constructor gets called
			//
			DepPEFile = new PE_FILE;

			if ( !DepPEFile )
			{
				return FALSE;
			}

			DepPEFile->Parent = PEFile;

			GetFullPathNameA(
				FileName,
				MAX_PATH,
				 DepPEFile->FilePath,
				&DepPEFile->FileName
			);

			if ( !PeOpenFile( DepPEFile->FileName, DepPEFile ) )
			{
				if ( !PeOpenFile( DepPEFile->FilePath, DepPEFile ) )
				{
					delete DepPEFile;

					return FALSE;
				}
			}
		}

		if ( Depth > 0 )
		{
			PIMAGE_THUNK_DATA LookupTable = ( PIMAGE_THUNK_DATA )( Base + CurrentDescriptor->OriginalFirstThunk );

			for ( PIMAGE_THUNK_DATA  CurrentLT = LookupTable;
				CurrentLT->u1.AddressOfData;
				CurrentLT++ )
			{
				if ( IMAGE_SNAP_BY_ORDINAL( CurrentLT->u1.Ordinal ) )
				{
					continue;
				}

				PIMAGE_IMPORT_BY_NAME ImportName = ( PIMAGE_IMPORT_BY_NAME )( Base + CurrentLT->u1.AddressOfData );

				if ( !ImportName || !ImportName->Name || !ImportName->Name[ NULL ] )
				{
					continue;
				}

				//
				// allocate empty dependency in vector
				//
				PEFile->Dependencies.push_back( { } );

				PPE_DEPENDENCY PeDependency = &PEFile->Dependencies.back( );
				PeDependency->File = DepPEFile;
				strcpy_s( PeDependency->Name, ImportName->Name );
			}

			if ( WasWalked == FALSE && PEFile->Parent == NULL )
			{
				//
				// recursively walk new files dependencies
				//
				if ( !PeWalkFileDependencies( DepPEFile, Depth - 1 ) )
				{
					PeCloseFile( DepPEFile );

					return FALSE;
				}
			}
		}
	}

	//
	// attempt to release some uneeded
	// memory
	//
	PEFile->FileData.clear( );
	PEFile->DosHeader = NULL;
	PEFile->NtHeaders = NULL;

	return TRUE;
}

BOOL
PeCloseFile(
	_Inout_ PPE_FILE PEFile
)
{
	//
	// check whether the pointer to file
	// name doesent lie within our array
	// indicating we allocated it in
	// PeOpenFile
	//
	if ( PEFile->FileName < PEFile->FilePath ||
		 PEFile->FileName > PEFile->FilePath + MAX_PATH )
	{
		free( PEFile->FileName );
	}

	return FALSE;
}