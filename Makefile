CC=g++
CXXFLAGS=-O2 -g -Wall -Wextra -pedantic -std=c++11
LDFLAGS=-Wl,-rpath=/usr/local/lib/gcc49/
SERVER=dserver.cpp dserver.h
all: dserver

dserver: $(SERVER)
	$(CC) $(CXXFLAGS) $(LDFLAGS) $(SERVER) -o $@
clean:
	rm -f dserver
