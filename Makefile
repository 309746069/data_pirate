CC=gcc
OBJECT=main.o \
       common.o \
       hunter.o \
       sender.o \
       cheater.o \
       queue.o \
       net_state.o \
       router.o \
       http.o \
       packet_info.o \
       gzip_wrapper.o \
       tcp_stream.o \
       stalker.o \
       rapist.o \
       tcp_sender.o \
       rectifier.o
       
TARGET=data_pirate
LIB= -lpcap -lnet -lpthread -lz
LOG=log.txt

all: $(TARGET)


$(TARGET): $(OBJECT)
	$(CC) -o $(TARGET) $(OBJECT) $(LIB)

run: $(TARGET)
	@echo "\033[1m[run]=====================\033[0m"
	@- ./$(TARGET)
	@echo "\033[1m[end]=====================\033[0m\n"

log:
	@date > $(LOG)
	make run >> $(LOG)
	@date >> $(LOG)


clean:
	-rm $(TARGET) *.o $(LOG)