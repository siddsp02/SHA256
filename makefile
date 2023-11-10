CC = gcc
# CFLAGS = -Wall -g

all: sha256.o tests main

sha256.o:
	$(CC) -c sha256.c -o sha256.o

tests: sha256.o
	$(CC) sha256.o tests.c -o tests

main: sha256.o
	$(CC) sha256.o main.c -o main