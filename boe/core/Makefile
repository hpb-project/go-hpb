# 1、准备工作，编译方式、目标文件名、依赖库路径的定义。
TOP=${PWD}
CROSS=
INSTALL_DIR=.

CC=${CROSS}gcc
CFLAGS  := -Wall -g -O3 -std=gnu99


OBJS =  common.o community.o tsu_connector.o axu_connector.o boe.o #.o文件与.cpp文件同名
LIB = libboe.so # 目标文件名


INCLUDE_PATH = -I .

# 依赖的lib名称
LD_LIB = 

all : $(LIB)

# 2. 生成.o文件 
%.o : %.c
	$(CC) $(CFLAGS) -fpic -c $< -o $@ $(INCLUDE_PATH) $(LIB_PATH) $(LD_LIB)

# 3. 生成动态库文件
$(LIB) : $(OBJS)
	rm -f $@
	$(CC) -shared -o $@ $(OBJS)
	rm -f $(OBJS)


# 4. 删除中间过程生成的文件 
clean:
	rm -f $(OBJS) $(TARGET) $(LIB)

install:
	cp -f $(LIB) $(INSTALL_DIR)
