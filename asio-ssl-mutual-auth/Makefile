CPP=g++
CFLAGS=-I.-DKSSL_DEBUG
DEPS = server.cpp

LDFLAGS=-lcrypto -lssl -lboost_system -lboost_filesystem -lpthread

%.o: %.cpp $(DEPS)
	$(CPP) -c -o $@ $< $(CFLAGS)

all: client server

server: server.o 
	g++ -o server server.o $(LDFLAGS)

client: client.o
	g++ -o client client.o $(LDFLAGS) $(CFLAGS)


.PHONY: clean

clean:
	rm -f *.o server client
