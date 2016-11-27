#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>


#define MY_INVALID_UID -1
#define MY_CURRENT_UID (getuid())
#define MY_CURRENT_EUID (geteuid())


/** RULES **/
#define MAX_RULE_STR_LEN 128
#define MAX_RULES_IN_POLICY 10
#define MAX_FD_TABLE 500

typedef struct _rule
{
	uid_t uid;
	enum {READ_ACCESS=0, WRITE_ACCESS, READ_EXCEPT_ACCESS, WRITE_ONLY_ACCESS} access;
	char filename[MAX_RULE_STR_LEN];
	char keyword[MAX_RULE_STR_LEN];  
} Rule;

Rule myPolicy[MAX_RULES_IN_POLICY];


typedef struct _fdtable
{
	int fd;
	const char *filename;
} FdTable;

FdTable myFdTable[MAX_FD_TABLE];
uint curentFdTableIndex = -1;

void add_file_descriptor(int file_desc, const char *path) 
{
	curentFdTableIndex++;

	if (curentFdTableIndex == MAX_FD_TABLE)
		printf("Error: Max file descriptor table has been reached");

	myFdTable[curentFdTableIndex].fd = file_desc;
	myFdTable[curentFdTableIndex].filename = path;
} 

const char *get_file_name(int file_desc)
{
	for (int i = 0; i <= curentFdTableIndex; i++)
	{
		if (myFdTable[i].fd == file_desc) 
		{
			return myFdTable[i].filename;
		}
	}
}

void search_string(char *str, char *prefix, char *suffix, int *start_index, int *end_index)
{   
	int prefixlen = strlen(prefix);
	int suffixlen = strlen(suffix);
    int strindex = 0;
    int opentags = 0;

    for ( ; *str; str++)
    {
    	strindex++;
        if (!memcmp(str, prefix, prefixlen))
        {
        	// only set the starting index if it's the parent of all nested tags
        	if (0 == opentags)
            	*start_index = strindex;
            opentags++;
        }
        else if (!memcmp(str, suffix, suffixlen))
        {
        	*end_index = strindex;

        	// so we can bypass any nested tags
        	if (opentags > 0)
        	{
        		opentags--;

        		// return on the last close tag
        		if (opentags == 0)
        			break;
        	}
        	else
        	{
        		break;
        	}
        }
    }
}

void initilize_rules() 
{
	//initialize the rules 
	for (int i = 0; i < MAX_RULES_IN_POLICY; i++)
	{
		myPolicy[i].uid = MY_INVALID_UID;
		myPolicy[i].keyword[0] = '\0';
		myPolicy[i].filename[0] = '\0';
	}

	//TEST
	myPolicy[0].uid = 1000;
	myPolicy[0].access = READ_EXCEPT_ACCESS;
	strcpy(myPolicy[0].filename, "secret.txt");
	strcpy(myPolicy[0].keyword, "SECRET");

	myPolicy[1].uid = 1000;
	myPolicy[1].access = WRITE_ACCESS;
	strcpy(myPolicy[1].filename, "secret2.txt");

	myPolicy[2].uid = 1000;
	myPolicy[2].access = WRITE_ONLY_ACCESS;
	strcpy(myPolicy[2].filename, "write_secret.txt");
	strcpy(myPolicy[2].keyword, "TOP_SECRET");

	// Initialize the file descriptor table
	for (int j = 0; j < MAX_FD_TABLE; j++)
	{
		myFdTable[j].fd = -1;
		myFdTable[j].filename = NULL;
	}
}

int my_open(const char *path, int oflags, ...) 
{
	initilize_rules();

	va_list args;
	va_start(args, oflags);

	int allowedAccess = 0x3; //default allow - this is a bit mask, first bit is read, second bit is write

	// holds the access flag
	int acc_mode = oflags & O_ACCMODE;

	//a flag to see if the current rule is the first rule fo rthe file
	int bFirstRule = 1; 


	//return value after policy checks
	int ret;

	// policy rules check
	for (int i = 0; i < MAX_RULES_IN_POLICY; i++)
	{
		// short circuit the check if the rule has an invalid uid
		if ( myPolicy[i].uid == MY_INVALID_UID )
		{
			break;
		}

		if ( (MY_CURRENT_UID == myPolicy[i].uid) || (MY_CURRENT_EUID == myPolicy[i].uid) )
		{
			//if the current uid or euid is specified in the rule
			// then see if the file being opened is also in the rule

			if (strcmp(path, myPolicy[i].filename) == 0) 
			{
				printf("File [%s] is being opened with Flags [%x]\n", path, oflags);
				//since the filenames are the same we now change the allowedAccess
				// to 0 (deny) - the actual rules will set the other permissions
				// we only do it if its the first rule
				if (bFirstRule)
				{
					allowedAccess = 0;
					bFirstRule = 0;
				}

				if ( (myPolicy[i].access == READ_ACCESS) || (myPolicy[i].access == READ_EXCEPT_ACCESS) )
				{
					allowedAccess |= 0x1; 
				}

				if ( (myPolicy[i].access == WRITE_ACCESS) || (myPolicy[i].access == WRITE_ONLY_ACCESS) )
				{
					allowedAccess |= 0x2; 
				}
			}
		}
	}


	if (acc_mode == O_RDONLY)
	{
		if (!(allowedAccess & 0x1)) //if it is not allowed
		{
			ret = -1;
			printf("The file [%s] is being opened for RDONLY [%d], but is not allowed\n", path, acc_mode);
		}
		else 
		{
			ret = open(path, O_RDONLY, args);
			add_file_descriptor(ret, path); 
		}
	}
	else if (acc_mode == O_WRONLY)
	{
		if (!(allowedAccess & 0x2)) //if it is not allowed
		{
			ret = -1;
			printf("The file [%s] is being opened for WRONLY [%d], but is not allowed\n", path, acc_mode);
		}
		else
		{
			ret = open(path, O_WRONLY, args);
			add_file_descriptor(ret, path);
		}
	}
	else if (acc_mode == O_RDWR)
	{
		if (!(allowedAccess == 0x3)) //if it is not allowed
		{
			ret = -1;
			printf("The file [%s] is being opened for RDWR [%d], but is not allowed\n", path, acc_mode);
		}
		else
		{
			ret = open(path, O_RDWR, args);
			add_file_descriptor(ret, path);
		}
	}
	else
	{
		ret = open(path, O_RDONLY, args);
		add_file_descriptor(ret, path);
	}


	va_end(args);

	return ret;
}

ssize_t my_read(int fildes, void *buf, size_t nbyte)
{
	// get the file path
	const char *path = get_file_name(fildes);

	int allowedAccess = 0x3; //default allow - this is a bit mask, first bit is read, second bit is write
	char *keyword;

	//a flag to see if the current rule is the first rule fo rthe file
	int bFirstRule = 1; 


	//return value after policy checks
	int ret;

	// policy rules check
	for (int i = 0; i < MAX_RULES_IN_POLICY; i++)
	{
		// short circuit the check if the rule has an invalid uid
		if ( myPolicy[i].uid == MY_INVALID_UID )
		{
			break;
		}

		if ( (MY_CURRENT_UID == myPolicy[i].uid) || (MY_CURRENT_EUID == myPolicy[i].uid) )
		{
			//if the current uid or euid is specified in the rule
			// then see if the file being opened is also in the rule

			if (strcmp(path, myPolicy[i].filename) == 0) 
			{
				printf("File [%s] is being opened for read\n", path);
				//since the filenames are the same we now change the allowedAccess
				// to 0 (deny) - the actual rules will set the other permissions
				// we only do it if its the first rule
				if (bFirstRule)
				{
					allowedAccess = 0;
					bFirstRule = 0;
				}

				if ( (myPolicy[i].access == READ_ACCESS) || (myPolicy[i].access == READ_EXCEPT_ACCESS) )
				{
					allowedAccess |= 0x1; 
					keyword = myPolicy[i].keyword;
				}
			}
		}
	}


	if (!(allowedAccess & 0x1)) 
	{
		ret = -1;
		printf("The file [%s] is being opened for read, but is not allowed\n", path);
	}
	else 
	{
		ret = read(fildes, buf, nbyte);


		// Mask the secret infromation if a keyword exist in the policy
		if (*keyword != '\0')
		{

			// Build the secret tag strings
			// This produces an opening tag like <SECRET>
			int keywordlen = (int)strlen(keyword);
			char prefix[keywordlen+3];
			prefix[0] = '<';
			memcpy(prefix+1, keyword, keywordlen+1);
			prefix[keywordlen+1] = '>';
			prefix[keywordlen+2] = '\0';

			// This produces a closing tag like </SECRET>
			char suffix[keywordlen+4];
			suffix[0] = '<';
			suffix[1] = '/';
			memcpy(suffix+2, keyword, keywordlen+2);
			suffix[keywordlen+2] = '>';
			suffix[keywordlen+3] = '\0';

			char *bufferptr = (char *)buf;
			while (*bufferptr)
    		{
				int start_index = -1, end_index = -1;
				search_string(bufferptr, prefix, suffix, &start_index, &end_index);
				
				if (-1 != start_index)
				{
					// Mask all the secret infomration
					buf = buf + start_index-1;

					// if there's no closing tag just mask until the end of current buffer
					if (-1 == end_index)
						end_index = (int)strlen(bufferptr);

					for (int k = start_index-1; k < end_index+keywordlen+2; k++)
					{
						*((char *)buf++) = '*';
						//printf("%c", *((char *)buf++));
					}
					bufferptr = bufferptr+end_index+keywordlen+2;
				}
				else
				{
					bufferptr++;	
				}
				
			}


			printf("\n");
		}
		
	}

	return ret;	
}

ssize_t my_write(int fildes, void *buf, size_t nbyte)
{
	// get the file path
	const char *path = get_file_name(fildes);
	
	printf("File desc path is: %s \n", path);

	int allowedAccess = 0x3; //default allow - this is a bit mask, first bit is read, second bit is write
	char *keyword;

	//a flag to see if the current rule is the first rule fo rthe file
	int bFirstRule = 1; 

	//return value after policy checks
	int ret;

	// policy rules check
	for (int i = 0; i < MAX_RULES_IN_POLICY; i++)
	{
		// short circuit the check if the rule has an invalid uid
		if ( myPolicy[i].uid == MY_INVALID_UID )
		{
			break;
		}

		if ( (MY_CURRENT_UID == myPolicy[i].uid) || (MY_CURRENT_EUID == myPolicy[i].uid) )
		{
			//if the current uid or euid is specified in the rule
			// then see if the file being opened is also in the rule

			if (strcmp(path, myPolicy[i].filename) == 0) 
			{
				printf("File [%s] is being opened for write\n", path);
				//since the filenames are the same we now change the allowedAccess
				// to 0 (deny) - the actual rules will set the other permissions
				// we only do it if its the first rule
				if (bFirstRule)
				{
					allowedAccess = 0;
					bFirstRule = 0;
				}

				if ( (myPolicy[i].access == WRITE_ACCESS) || (myPolicy[i].access == WRITE_ONLY_ACCESS) )
				{
					allowedAccess |= 0x2; 
					keyword = myPolicy[i].keyword;
				}
			}
		}
	}


	// check if it's open for WRONLY or RDWR
	if (!(allowedAccess & 0x2) || !(allowedAccess & 0x3)) 
	{
		ret = -1;
		printf("The file [%s] is being opened for write, but is not allowed\n", path);
	}
	else 
	{
		


		// Mask the secret infromation if a keyword exist in the policy
		if (*keyword != '\0')
		{

			// Build the secret tag strings
			// This produces an opening tag like <SECRET>
			int keywordlen = (int)strlen(keyword);
			char prefix[keywordlen+3];
			prefix[0] = '<';
			memcpy(prefix+1, keyword, keywordlen+1);
			prefix[keywordlen+1] = '>';
			prefix[keywordlen+2] = '\0';

			// This produces a closing tag like </SECRET>
			char suffix[keywordlen+4];
			suffix[0] = '<';
			suffix[1] = '/';
			memcpy(suffix+2, keyword, keywordlen+2);
			suffix[keywordlen+2] = '>';
			suffix[keywordlen+3] = '\0';

			char *bufferptr = (char *)buf;
			while (*bufferptr)
    		{
				int start_index = -1, end_index = -1;
				search_string(bufferptr, prefix, suffix, &start_index, &end_index);

				//printf("output: %i, %i", start_index, end_index);
				
				//printf("indexes: %i %i \n", start_index, end_index);
				if (-1 != start_index)
				{
					// Mask all the secret infomration
					buf = buf + start_index-1;
					int output_len = end_index+keywordlen+2-start_index;
					char write_buffer[output_len];
					memcpy(write_buffer, buf, output_len+1);
					//printf("output to save: %s \n", write_buffer);
					//printf("output size: %i \n", end_index+keywordlen+2-start_index);
					ret = write(fildes, write_buffer, output_len+1);
					

					//printf("indexes: %i \n", ret);
					//printf("error: %s \n", strerror(errno));
					
					// // if there's no closing tag just mask until the end of current buffer
					// if (-1 == end_index)
					// 	end_index = (int)strlen(bufferptr);

					// for (int k = start_index-1; k < end_index+keywordlen+2; k++)
					// {
					// 	*((char *)buf++) = '*';
					// 	//printf("%c", *((char *)buf++));
					// }
					bufferptr = bufferptr+end_index+keywordlen+2;
				}
				else
				{
					bufferptr++;	
				}
				
			}

			


			printf("\n");
		}
		
	}

	return ret;
}

int my_close(int fildes)
{
	return close(fildes);
}