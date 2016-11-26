#include <stdio.h>
#include <fcntl.h>
#include "reference-monit.h"

#define BUF_SIZE 8192

void run_test_cases(void);
void clear_buffer(char buf[]);

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
	char buffer[BUF_SIZE];

	// Read Test case 1
	file_desc = my_open("secret.txt", O_RDONLY);

	if (file_desc == -1)
	{
		printf("Error opening the file. \n");
	}
	else
	{
		
		my_read(file_desc, buffer, 500);
		printf("File read output: %s \n", buffer);		
	}
	clear_buffer(buffer);
	my_close(file_desc);

	// Write Test Case 1
	int fd1 = my_open("write_secret.txt", O_WRONLY);
	if (fd1 == -1)
	{
		printf("Error opening the file. \n");
	}
	else
	{
		char buffer[BUF_SIZE] = "<SECRET>This is a secret</SECRET><TOP_SECRET>This is a top secret</TOP_SECRET>";
		my_write(fd1, buffer, 500);
	}
	my_close(fd1);

}

void clear_buffer(char buf[])
{
	for (int i=0; i < BUF_SIZE; i++)
	{
		buf[i] = '\0';
	}
}