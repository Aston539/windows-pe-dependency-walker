#include <iostream>
#include <windows.h>
#include <string>

#include "pefile.h"

VOID
PrintFileDependencies(
	PPE_FILE PEFile,
	ULONG IndentCount = NULL
)
{
	for ( ULONG I = 0; I < IndentCount; I++ )
	{
		printf( "\t" );
	}

	printf( "%s: \n", PEFile->FileName );

	PPE_FILE LastFile = NULL;
	for ( auto& Dependency : PEFile->Dependencies )
	{
		if ( ( UINT_PTR )LastFile != ( UINT_PTR )Dependency.File )
		{
			PrintFileDependencies( Dependency.File, IndentCount + 1 );
		}

		for ( ULONG I = 0; I < IndentCount; I++ )
		{
			printf( "\t" );
		}

		printf( "\t\t%s\n", Dependency.Name );

		LastFile = Dependency.File;
	}
}

int main( int argc, char** argv )
{
	if ( argc <= 1 )
	{
		printf( "Invalid usage < TargetPEPath > < ( OPTIONAL ) Depth > \n" );
	
		system( "pause" );
	
		return 0x1;
	}

	LONG RecursionDepth = 1;

	if ( argc > 2 )
	{
		RecursionDepth = std::stol( argv[ 2 ] );
	}

	PE_FILE TargetFile = { };
	if ( !PeOpenFile( argv[ 1 ], &TargetFile ) )
	{
		printf( "Failed to open file!\n" );

		system( "pause" );

		return 0x2;
	}

	if ( !PeWalkFileDependencies( &TargetFile, RecursionDepth ) )
	{
		printf( "Failed to walk file dependencies!\n" );

		system( "pause" );

		return 0x3;
	}

	PrintFileDependencies( &TargetFile );

	if ( !PeCloseFile( &TargetFile ) )
	{
		printf( "Failed to close file!\n" );
	}

	system( "pause" );

	return 0x0;
}