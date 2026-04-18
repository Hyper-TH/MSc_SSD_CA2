CC ?= gcc
TARGET = aes_test
LIB_TARGET = rijndael.so

.PHONY: all clean

all: main $(TARGET) $(LIB_TARGET)

# Target for main.exe
main: rijndael.o main.c
	$(CC) -o main main.c rijndael.o

# Target for aes_test.exe (to test with ctypes from python)
$(TARGET): main.c rijndael.c
	$(CC) main.c rijndael.c -o $(TARGET)

rijndael.o: rijndael.c rijndael.h substitution.h
	$(CC) -o rijndael.o -fPIC -c rijndael.c

rijndael.so: rijndael.o
	$(CC) -o rijndael.so -shared rijndael.o

# Build the shared library for Python integration
$(LIB_TARGET): rijndael.o
	$(CC) -shared rijndael.o -o $(LIB_TARGET)

clean:
	rm -f *.o *.so *.exe $(TARGET)