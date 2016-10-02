#ifndef DSERVER_H
#define DSERVER_H

#include <fstream>
#include <stdio.h>
#include <regex>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

const int BUFSIZE = 1024;

void help();
void listen_wrapper(int server_socket);
int fork_handler();
int get_new_client(int server_socket);
void send_msg(int socket, char *msg);
void handle_communication(int server_socket);
void init_server(int port);
void serve(int client_socket);
int get_socket();

#endif
