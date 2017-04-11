#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

int add_number( int num1, int num2 )
{
	int sum;

	sum = num1 - num2;

	return sum;
}

int main(int argc, char* argv[])
{
	int num1, num2;
	int return_value;

	if( argc < 2 )
	{
		printf("You need to enter two numbers to add.\n");
		printf("addnum.exe num1 num2\n");

		return 0;
	}

	num1 = atoi(argv[1]);
	num2 = atoi(argv[2]);

	return_value = add_number( num1, num2 );

	printf("Sum of %d + %d = %d",num1, num2, return_value );

	return 0;
}


	
