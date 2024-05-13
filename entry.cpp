#include <iostream>
#include <windows.h>

#include "pefile.h"

int main( int argc, char** argv )
{
	//if ( argc <= 1 )
	//{
	//	printf( "Invalid usage < TargetPEPath > \n" );
	//
	//	system( "pause" );
	//
	//	return 0x1;
	//}

	freopen_s( ( FILE** )stdout, "CONOUT$", "w", stdout );

	PE_FILE TargetFile = { };
	if ( !PeOpenFile( "C:\\Users\\trapp\\Documents\\Programming\\Projects\\windows-pe-sandbox\\x64\\Release\\windows-pe-sandbox.exe", &TargetFile ) )
	{
		return 0x2;
	}

	PeWalkFileDependencies( &TargetFile );

	printf( "%s: \n", TargetFile.FileName );
	PPE_FILE LastFile = NULL;
	for ( auto& Dependency : TargetFile.Dependencies )
	{
		if ( ( UINT_PTR )LastFile != ( UINT_PTR )Dependency.File )
		{
			printf( "\t\t%s: \n", Dependency.File->FileName );
			for ( auto& RecursiveDependency : Dependency.File->Dependencies )
			{
				printf( "\t\t\t%s -> %s\n", RecursiveDependency.File->FileName, RecursiveDependency.Name );
			}
		}

		printf( "\t%s -> %s\n", Dependency.File->FileName, Dependency.Name );
	}

	return 0x0;
}