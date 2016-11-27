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

		printf("\n Running all test cases: \n\n");
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

	// Open Test case 1 - policy enforcement
	printf("Open Test case 1 - policy enforcement  \n");
	file_desc = my_open("secret.txt", O_WRONLY);
	if (file_desc == -1)
	{
		printf("Error opening the file. \n\n");
	}
	my_close(file_desc);

	// Read Test case 1 - reading a file with secrets and plain text
	printf("Read Test case 1 - reading a file with secrets and plain text \n");
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

	// Read Test case 2 - reading a file with secrets but the buffer read size 
	// ends before the secret block ends
	printf("Read Test case 2 - the buffer read size ends before the secret block ends \n");
	file_desc = my_open("secret.txt", O_RDONLY);

	if (file_desc == -1)
	{
		printf("Error opening the file. \n");
	}
	else
	{
		
		my_read(file_desc, buffer, 20);
		printf("File read output: %s \n", buffer);		
	}
	clear_buffer(buffer);
	my_close(file_desc);

	// Write Test Case 1
	printf("Write Test Case 1 - writing a top secret block to file \n");
	file_desc = my_open("write_secret.txt", O_WRONLY);
	if (file_desc == -1)
	{
		printf("Error opening the file. \n");
	}
	else
	{
		char buffer[BUF_SIZE] = "<SECRET>This is a secret</SECRET><TOP_SECRET>This is a top secret</TOP_SECRET>";
		my_write(file_desc, buffer, BUF_SIZE);
	}
	clear_buffer(buffer);
	my_close(file_desc);

	// Write Test Case 1
	printf("Write Test Case 2 - writing incomplete top secret block to file \n");
	file_desc = my_open("write_secret.txt", O_WRONLY);
	if (file_desc == -1)
	{
		printf("Error opening the file. \n");
	}
	else
	{
		char buffer[BUF_SIZE] = "<TOP_SECRET>This is a top";
		my_write(file_desc, buffer, BUF_SIZE);
	}
	clear_buffer(buffer);
	my_close(file_desc);


}

void clear_buffer(char buf[])
{
	for (int i=0; i < BUF_SIZE; i++)
	{
		buf[i] = '\0';
	}
}