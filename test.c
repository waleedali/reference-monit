#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
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
	printf("1. Open Test case - policy enforcement  \n");
	file_desc = my_open("secret.txt", O_WRONLY);
	if (file_desc == -1)
	{
		printf("Error opening the file. \n\n");
	}
	my_close(file_desc);

	printf("2. Open Test case - policy enforcement  \n");
	file_desc = my_open("write_secret.txt", O_RDONLY);
	if (file_desc == -1)
	{
		printf("Error opening the file. \n\n");
	}
	my_close(file_desc);

	printf("3. Open Test case - allow write policy  \n");
	file_desc = my_open("write_secret.txt", O_WRONLY);
	if (file_desc == -1)
	{
		printf("error: %s \n", strerror(errno));
		printf("Error opening the file. \n\n");
	}
	my_close(file_desc);
	printf("\n");

	printf("4. Open Test case - proper error reporting when trying to read a file that doesn't exist  \n");
	file_desc = my_open("write_secret1.txt", O_RDONLY);
	if (file_desc == -1)
	{
		printf("error: %s \n", strerror(errno));
		printf("Error opening the file. \n\n");
	}
	my_close(file_desc);

	// Read Test case 1 - reading a file with secrets and plain text
	printf("5. Read Test case - reading a file with secrets and plain text \n");
	file_desc = my_open("secret.txt", O_RDONLY);

	if (file_desc == -1)
	{
		printf("Error opening the file. \n");
	}
	else
	{
		my_read(file_desc, buffer, BUF_SIZE);
		printf("File read output: %s \n", buffer);		
	}
	clear_buffer(buffer);
	my_close(file_desc);

	// Read Test case 2 - reading a file with secrets but the buffer read size 
	// ends before the secret block ends
	printf("6. Read Test case - the buffer read size ends before the secret block ends \n");
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
	printf("\n");

	// Read Test case - read with three nested secret tags 
	// ends before the secret block ends
	printf("7. Read Test case - read with three nested secret tags \n");
	file_desc = my_open("secret3.txt", O_RDONLY);

	if (file_desc == -1)
	{
		printf("Error opening the file. \n");
	}
	else
	{
		
		my_read(file_desc, buffer, BUF_SIZE);
		printf("File read output: %s \n", buffer);		
	}
	clear_buffer(buffer);
	my_close(file_desc);
	printf("\n");

	// Write Test Case 
	printf("8. Write Test Case - writing a top secret block to file \n");
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

	// Write Test Case 
	printf("9. Write Test Case - writing incomplete top secret block to file \n");
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

	// Write Test Case 1
	printf("10. Write Test Case - writing with text that doesn't include secret keyword tag \n");
	file_desc = my_open("write_secret.txt", O_WRONLY);
	if (file_desc == -1)
	{
		printf("Error opening the file. \n");
	}
	else
	{
		char buffer[BUF_SIZE] = "This is a normal text without secret tags";
		my_write(file_desc, buffer, BUF_SIZE);
	}
	clear_buffer(buffer);
	my_close(file_desc);

	printf("11. Bypassing Test case - writes to file anyway event a buffer limit was provided  \n");
	file_desc = my_open("write_secret.txt", O_WRONLY);
	if (file_desc == -1)
	{
		printf("error: %s \n", strerror(errno));
		printf("Error opening the file. \n\n");
	}
	else
	{
		
		char buffer[BUF_SIZE] = "<TOP_SECRET>This is a top text with limiting buffer size </TOP_SECRET>";
		my_write(file_desc, buffer, 10);		
	}
	clear_buffer(buffer);
	my_close(file_desc);
	printf("\n");

	printf("12. Bypassing Test case - additional data is written to file if two tag closings are added the buffer to write \n");
	file_desc = my_open("write_secret.txt", O_WRONLY);
	if (file_desc == -1)
	{
		printf("error: %s \n", strerror(errno));
		printf("Error opening the file. \n\n");
	}
	else
	{
		
		char buffer[BUF_SIZE] = "<TOP_SECRET>This is a top </TOP_SECRET> text with limiting buffer size </TOP_SECRET>";
		my_write(file_desc, buffer, 10);		
	}
	clear_buffer(buffer);
	my_close(file_desc);
	printf("\n");

	printf("13. Bypassing Test case -  secret data is revealed if additional closing tag is present\n");
	file_desc = my_open("secret4.txt", O_RDONLY);

	if (file_desc == -1)
	{
		printf("Error opening the file. \n");
	}
	else
	{
		
		my_read(file_desc, buffer, BUF_SIZE);
		printf("File read output: %s \n", buffer);		
	}
	clear_buffer(buffer);
	my_close(file_desc);
	printf("\n");

	printf("14. Bypassing Test case -  secret data is revealed if if the opening tag of the parent tag of nested tags has a one or more corrupt characters\n");
	file_desc = my_open("secret5.txt", O_RDONLY);

	if (file_desc == -1)
	{
		printf("Error opening the file. \n");
	}
	else
	{
		
		my_read(file_desc, buffer, BUF_SIZE);
		printf("File read output: %s \n", buffer);		
	}
	clear_buffer(buffer);
	my_close(file_desc);
	printf("\n");

	printf("15. Bypassing Test case -  if the of the hex code of the text editor was edited to add terminating character, the secret data can be revealed\n");
	file_desc = my_open("secret6.txt", O_RDONLY);

	if (file_desc == -1)
	{
		printf("Error opening the file. \n");
	}
	else
	{
		
		my_read(file_desc, buffer, BUF_SIZE);
		printf("File read output: %s \n", buffer);		
	}
	clear_buffer(buffer);
	my_close(file_desc);
	printf("\n");

}

void clear_buffer(char buf[])
{
	for (int i=0; i < BUF_SIZE; i++)
	{
		buf[i] = '\0';
	}
}