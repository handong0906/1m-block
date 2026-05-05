CC = g++
LIBS = -lnetfilter_queue

TARGET = 1m-block
SOURCE = main.cpp

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) -o $(TARGET) $(SOURCE) $(LIBS)

set-rule:
	sudo iptables -A INPUT -j NFQUEUE --queue-num 0
	sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0

unset-rule:
	sudo iptables -F

clean:
	rm -f $(TARGET)