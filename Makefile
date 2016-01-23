CC=gcc
OBJECT=main.o robber.o common.o hunter.o sender.o cheater.o queue.o
TARGET=data_pirate
LIB= -lpcap -lnet -lpthread
LOG=log.txt

all: $(TARGET)


$(TARGET): $(OBJECT)
	$(CC) -o $(TARGET) $(OBJECT) $(LIB)

run: $(TARGET)
	@echo "\033[1m[run]====================="
	@- ./$(TARGET)
	@echo "[end]=====================\033[0m\n"

log:
	@date > $(LOG)
	make run >> $(LOG)
	@date >> $(LOG)


clean:
	-rm $(TARGET) *.o $(LOG)