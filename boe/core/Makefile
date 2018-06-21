# 1、准备工作，编译方式、目标文件名、依赖库路径的定义。
TOP=${PWD}
OUT_FILE_NAME=libboe.a


CROSS=
INC= -I .

CC=${CROSS}gcc
CFLAGS  := -Wall -g -fPIC -c -fpermissive

OBJ_DIR=./obj
OUT_DIR=./lib

$(OUT_FILE_NAME): $(patsubst %.c,$(OBJ_DIR)/%.o,$(wildcard *.c))
	ar -r -o $(OUT_DIR)/$@ $^

$(OBJ_DIR)/%.o:%.c dirmake
	$(CC) -c $(INC) $(CFLAGS) -o $@ $<

dirmake:
	@mkdir -p $(OUT_DIR)
	@mkdir -p $(OBJ_DIR)

clean:
	rm -f $(OBJ_DIR)/*.o $(OUT_DIR)/$(OUT_FILE_NAME) 

rebuild: clean build


