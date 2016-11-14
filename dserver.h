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
#include <signal.h>
#include <time.h>

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
const int LEASETIME = 3600;
const char * BROADCAST = "255.255.255.255";
struct range *r = NULL;

void help();
void listen_wrapper(int server_socket);
char * ip_to_str(struct in_addr * addr);
uint32_t str_to_ip(const char * addr);
char * uint32_t_to_str(uint32_t ip);
int fork_handler();
int get_new_client(int server_socket);
void send_msg(unsigned char * buffer, const char * sendto_addr);
void handle_communication(int server_socket);
void init_server(int port);
void serve(int client_socket);
int get_socket();
void send_ack(unsigned char * buffer);
void send_nak(unsigned char *buffer);
void send_offer(unsigned char * buffer);
void release(unsigned char * buffer);
void prepare_offer(unsigned char * buffer);
void rewrite_ip_address(unsigned char *buffer, uint32_t ip);
void debug_discover(unsigned char * buffer);
uint32_t increment_ip_address(uint32_t add);
void get_client_mac_address(unsigned char * buffer, char * str);
void lease(uint32_t addr, char * chaddr_str, int print);
uint32_t check_client_leases(char * chaddr_str);
void get_requested_ip_address(unsigned char * buffer, char * str);
void lease_expiration_check();

void debug_range(struct range *r);
void debug_buffer(unsigned char * buffer, int rcvd);
void debug_field_hex(const char * intro, unsigned char * field, int len);
void debug_field_int(const char * intro, unsigned char * field, int len);
#endif
