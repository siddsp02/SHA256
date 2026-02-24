CC = gcc

all: sha256.o sha256.dll tests main

sha256.o:
	$(CC) -c sha256.c -o sha256.o

# Right now, building the shared lib is only for Windows,
# but this will be changed later on.
sha256.dll: sha256.o
	$(CC) -shared -o sha256.dll sha256.o

tests: sha256.o
	$(CC) sha256.o tests.c -o tests

main: sha256.o
	$(CC) sha256.o main.c -o main