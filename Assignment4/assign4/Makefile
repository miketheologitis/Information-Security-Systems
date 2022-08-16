CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
OBJFILES = main.o rsa.o utils.o

TARGET = assign_4


all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) $(DBG) -o $(TARGET) $(OBJFILES)

clean:
	rm -f $(TARGET) *.o
