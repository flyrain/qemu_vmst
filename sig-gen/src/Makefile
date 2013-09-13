LIBS=-L./xed2/xed2-ia32/lib -lxed
CFLAGS=-I./xed2/xed2-ia32/include 

SRC =  code_init.c determineOsVersion.c getPgd.c main.c md5c.c mddriver.c memload.c memory.c pageMd5Comparison.c vtop.c

OBJ = code_init.o determineOsVersion.o getPgd.o main.o md5c.o mddriver.o memload.o memory.o pageMd5Comparison.o vtop.o

TARGET = signa

$(TARGET): $(OBJ)
	gcc  -o $(TARGET) $(OBJ)  $(LIBS) $(CFLAGS) -g

all: $(TARGET) 



clean:
	rm -f  $(TARGET) $(OBJ)
