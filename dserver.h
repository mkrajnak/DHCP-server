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
#include <limits.h>

const int DHCP_NONE = 0;
const int DHCP_DISCOVER = 1;
const int DHCP_OFFER = 2;
const int DHCP_REQUEST = 3;
const int DHCP_DECLINE = 4;
const int DHCP_ACK = 5;
const int DHCP_NAK = 6;
const int DHCP_RELEASE = 7;
const int DHCP_INFORM	 = 8;
const int BUFSIZE = 512;

void help();
void listen_wrapper(int server_socket);
int fork_handler();
int get_new_client(int server_socket);
void send_msg(int socket, char *msg);
void handle_communication(int server_socket);
void init_server(int port);
void serve(int client_socket);
int get_socket();
void handle_rqst(int rcvd, unsigned char * buffer);

#endif
