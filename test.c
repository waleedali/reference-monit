#include <stdio.h>
#include <fcntl.h>
#include "reference-monit.h"

#define BUF_SIZE 8192

void run_test_cases(void);

int main(int argc, char *argv[])
{
	puts("Starting waleeds test program:");

	int file_desc;

	if (2 != argc)
	{
		printf("\n Usage: \n");
		printf("\n test [filename] \n");
		printf("\n test (without a filename, runs all test) \n");

		printf("\n Running all test cases: \n");
		run_test_cases();

		return 0;
	}

	file_desc = my_open(argv[1], O_RDONLY);

	return 0;
}

void run_test_cases() 
{
	int file_desc;
	file_desc = my_open("secret.txt", O_RDONLY);

	if (file_desc == -1)
	{
		printf("Error opening the file.");
	}
	else
	{
		char buffer[BUF_SIZE];
		my_read(file_desc, buffer, 500);
		printf("%s \n", buffer);		
	}


}

