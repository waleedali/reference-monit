PWD := $(shell pwd)
CC := gcc

all:
	$(CC) -c -fPIC -o reference-monit.o reference-monit.c
	$(CC) -shared -fPIC -o reference-monit.so reference-monit.o 
	$(CC) -L$(PWD) -o test test.c reference-monit.so

clean:
	rm -f test 
