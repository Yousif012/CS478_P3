CC = g++
CFLAGS = -Wall -O2 -std=c++11
LDFLAGS = -lssl -lcrypto

TARGET = encrypt

all: $(TARGET)

$(TARGET): encrypt.cpp
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET)
