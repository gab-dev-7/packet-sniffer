CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = sniffer

all: $(TARGET)

$(TARGET): sniffer.c
	$(CC) $(CFLAGS) -o $(TARGET) sniffer.c

clean:
	rm -f $(TARGET) *.pcap
