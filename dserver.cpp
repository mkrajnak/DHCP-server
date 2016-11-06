/**
* Project: DHCP server created for ISA course at fit.vutbr.cz
* Author:  Martin Krajnak
* Mail:   xkrajn02@stud.fit.vutbr.cz
* Date:   2.10.2016
*/

#include "dserver.h"
using namespace std;

struct lease_item{
  uint32_t mac_addr;
  uint32_t ip_addr;
  struct tm *lease_end;

}lease_item;

struct range{
  uint32_t network;         // address range from stdin
  int cidr;                         // prefix
  uint32_t server_address;          // server ip address
  uint32_t next_usable;             // first_usable ip address from diven range
  uint32_t mask;                    // network_mask
  uint32_t broadcast;               // broadcast
  vector <uint32_t> restricted;
  vector <uint32_t> pool;
  vector <string> leased_list;
}range;

/*
* INIT struct
*/
struct range * init(){
  struct range * r = NULL;
  r = (struct range *) malloc(sizeof(struct range));
  if (r == NULL) {
    perror("could not allocate memmory");
  }
  r->network = 0;
  r->cidr = 0;
  r->server_address = 0;
  r->next_usable = 0;
  r->mask = 0;
  r->broadcast = 0;
  return r;
}

void destroy(int sig){
  free(r);

  signal(sig, SIG_IGN);
  exit(EXIT_SUCCESS);
}

void debug_range(struct range *r){
  printf("Address: %s/%d\n", uint32_t_to_str(r->network), r->cidr);
  printf("My address: %s\n", uint32_t_to_str(r->server_address));
  printf("Whos next?: %s\n", uint32_t_to_str(r->next_usable));
  printf("Mask: %s\n", uint32_t_to_str(r->mask));
  printf("Broadcast: %s\n", uint32_t_to_str(r->broadcast));

  std::cout << "Vector" << std::endl;
  for (auto & element : r->restricted) {
    cout  << uint32_t_to_str(element) << endl;
  }

  std::cout << "pool" << std::endl;
  for (auto & element : r->pool) {
    cout  << uint32_t_to_str(element) << endl;
  }
  std::cout << "End" << std::endl;
}

/**
* Parsing numeric values + error detection
*/
int check_num_args(char *arg)
{
   	char *white = NULL;
   	int num = 0;
    num = (int) strtod(arg, &white);
   	if(strlen(white) != 0)
   	{
     	fprintf(stderr,"Unexpected input \"%s\"\n",white);
     	exit(EXIT_FAILURE);
   	}
   	else
   	  return num;   //no char detected, numeric value is returned
}

/**
* HELP
*/
void help()
{
  printf("DHCP server implemented by Martin Krajnak <xkrajn02@stud.fit.vutbr.cz>:\n"
        "Usage:\t ./dserver -p 192.168.0.0/24 [-e 192.168.0.1,192.168.0.2]\n"
        "\t\t./dserver -p 192.168.0.0/24 -s static.txt\n"
        "\t -p <ip_address/mask> is network ip addess representing range\n"
        "\t -e [ip_addresses] are reserved ip addresses which are not allowed to\n"
        "be provided to clients, separated by comma \n"
      );
}

/**
* Send broad cast message
*/
void send_msg(unsigned char * buffer){
  int fd;
  // UDP socket
  struct sockaddr_in addr;
  // address data structure

  if ((fd=socket(AF_INET,SOCK_DGRAM,0)) < 0) // create a UDP socket for broadcast
    perror("Socket() failed");

  memset(&addr,0,sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_addr.s_addr=inet_addr("255.255.255.255"); // set the broadcast address
  addr.sin_port=htons(68);
  // set the broadcast port
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    perror("socket failed()");
  int on = 1;
  // set socket to send broadcast messages
  if ((setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on))) == -1)
    perror("setsockopt failed()");

  if (sendto(fd,buffer, BUFSIZE,0,(struct sockaddr *) &addr, sizeof(addr)) < 0) // send data without EOL
    perror("sendto");

  if ((close(fd)) == -1)
    // close the socket
    perror("close() failed");
  printf("Sent\n");

}

/**
* Communicate with client
* Messages DISCOVER, OFFER, REQUEST, ACK, NACK, RELEASE
*/
void serve(int srv_socket)
{
  socklen_t length;
  struct sockaddr_in client;
  unsigned char buffer[BUFSIZE];
  memset( buffer, 0 ,sizeof(buffer));

  length = sizeof(client);
  int rcvd = 0; // recieved data
  while ((rcvd = recvfrom(srv_socket, buffer, BUFSIZE, 0, (struct sockaddr *)&client, &length)) >= 0)
  {
    printf("Discover received from %s, port %d\n",inet_ntoa(client.sin_addr),ntohs(client.sin_port));
    printf("Message:\n");// \"%d\":end\n", buffer[0]);

    switch (buffer[242]) {
      case (int) 1:
        send_offer(buffer, rcvd);
        break;
      case (int) 3:
        send_ack(buffer, rcvd);
        break;
    }

    memset( buffer, 0 ,sizeof(buffer));
  }
  close(srv_socket);
}

void send_offer(unsigned char * buffer, int rcvd){

  handle_discover(rcvd, buffer);
  prepare_offer(buffer);
  send_msg(buffer);
}

void send_ack(unsigned char * buffer, int rcvd){

  handle_discover(rcvd, buffer);
  prepare_ack(buffer);
  send_msg(buffer);
}

void prepare_ack(unsigned char *buffer){
  prepare_offer(buffer);
  buffer[242] = (int) 5;
}

void rewrite_ip_address(unsigned char *buffer, uint32_t ip){
  for (int i = 0; i < 4; i++) {
    buffer[i] = (ip >> (i*8)) & 0xFF;
  }
}

void get_client_mac_address(unsigned char * buffer, char * str)
{
  unsigned char chaddr[6];
  memcpy(chaddr, &buffer[28], 6);

  sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",chaddr[0],
        chaddr[1], chaddr[2], chaddr[3], chaddr[4],chaddr[5]);
  str[18]='\0';
  //debug_field_hex("chaddr: " , chaddr, 6);
}

void print_lease(unsigned char *buffer, uint32_t addr){

  char chaddr_str[18];
  get_client_mac_address(buffer, chaddr_str);

  //2016-09-29_13:45
  time_t rawtime;
  struct tm * timeinfo;
  char ct_buffer[20];      // current time buffer
  char le_buffer[20];      // lease end

  time (&rawtime);
  timeinfo = localtime (&rawtime);
  strftime (ct_buffer,20,"%F_%R",timeinfo);

  timeinfo->tm_hour +=1;
  strftime (le_buffer,20,"%F_%R",timeinfo);
  printf("%s %s %s %s\n", chaddr_str, uint32_t_to_str(addr), ct_buffer, le_buffer);
}

void prepare_offer(unsigned char * buffer)
{
  r->leased_list.push_back(uint32_t_to_str(r->next_usable));
  print_lease(buffer, r->next_usable);

  rewrite_ip_address(&buffer[16], r->next_usable);          //write ip to buffer
  r->next_usable = increment_ip_address(r->next_usable);    // increment ip add

  rewrite_ip_address(&buffer[20], r->server_address);

  buffer[0] = (int) 2;      // msg type to reply
  buffer[242] = (int) 2;    // msg type to offer

  buffer[243] = (int) 1;    // option id
  buffer[244] = (int) 4;    // size in Bytes
  rewrite_ip_address(&buffer[245], r->mask);

  buffer[249] = (int) 54;   // next server ip
  buffer[250] = (int) 4;
  rewrite_ip_address(&buffer[251], r->server_address);

  buffer[255] = (int) 51;   // lease time
  buffer[256] = (int) 4;

  buffer[257] = (int) 0;
  buffer[258] = (int) 0;
  buffer[259] = (int) 0x0e;
  buffer[260] = (int) 0x10;

  buffer[261] = (int) 255;  //end

  bzero(&buffer[262],511-262);  //make sure garbage is deleted
  //debug_buffer(buffer, 512);
}


/**
* receive and parse dhcp packet
*/
void handle_discover(int rcvd, unsigned char * buffer){

  int op = buffer[0];         // Request 1, Reply 2
  int h_type = buffer[1];
  int h_len = buffer[2];
  int hops = buffer[3];

  printf("%d\n", op);
  printf("%d\n", h_type);
  printf("%d\n", h_len );
  printf("%d\n", hops);

  unsigned char xid[4];
  memcpy(xid, &buffer[4], 4);
  debug_field_hex("xid :0x", xid, sizeof(xid));

  unsigned char secs[2];
  memcpy(secs, &buffer[8], 2);
  debug_field_int("secs :", secs, sizeof(secs));

  unsigned char flags[2];
  memcpy(flags, &buffer[10], 2);
  debug_field_int("flags :", flags, sizeof(flags));

  unsigned char ciadr[4];
  memcpy(ciadr, &buffer[12], 4);
  debug_field_int("ciadr :", ciadr, sizeof(ciadr));

  unsigned char yaddr[4];
  memcpy(yaddr, &buffer[16], 4);
  debug_field_int("yaddr :", yaddr, sizeof(yaddr));

  unsigned char siaddr[4];
  memcpy(siaddr, &buffer[20], 4);
  debug_field_int("siaddr :", siaddr, sizeof(siaddr));

  unsigned char giaddr[4];
  memcpy(giaddr, &buffer[24], 4);
  debug_field_int("giaddr :", giaddr, sizeof(giaddr));

  unsigned char chaddr[16];
  memcpy(chaddr, &buffer[28], 16);
  debug_field_hex("chaddr :0x", chaddr, sizeof(chaddr));

  unsigned char sname[64];
  memcpy(sname, &buffer[44], 64);
  printf("sname: %s\n", sname);

  unsigned char magic_cookie[4];
  memcpy(magic_cookie, &buffer[236], 4);
  debug_field_hex("magic_cookie: ", magic_cookie, sizeof(magic_cookie));

  //debug_buffer(buffer, rcvd);

  if (strncmp((char*)buffer,"END.",4) == 0){    // "END." string exits application
    printf("closing socket\n");
    return;
  }
}

void debug_field_int(const char * intro, unsigned char * field, int len)
{
  printf("%s", intro);
  for (int i = 0; i < len; i++) {
    printf("%d ",field[i]);
  }
  printf("\n");
}

void debug_field_hex(const char * intro, unsigned char * field, int len)
{
  printf("%s", intro);
  for (int i = 0; i < len; i++) {
    printf("%02x ",field[i]);
  }
  printf("\n");
}

void debug_buffer(unsigned char * buffer, int rcvd)
{
  printf("ID \t|INT\t|CHAR\t|HEX\t|\n");
  for (int i = 0; i < rcvd; i++) {
    printf(" %4d| %4d\t| %4c\t| %02x\t\n",i , buffer[i], buffer[i], buffer[i]);
  }
  printf("--------------END----------\n");
}

/**
* Try to get socket
*/
int get_socket()
{
  int server_socket = 0;
  if((server_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)  // creating socket
  {
    perror("SOCKERR");
    exit(EXIT_FAILURE);
  }
  return server_socket;
}

/**
* INITIALIZING connection
*/
void init_server(int port)
{
  int server_socket = get_socket();
  // prepare address for bind
  struct sockaddr_in sw;            //setting up server address
  memset(&sw, 0, sizeof(sw));       // setting up struct for connect
  sw.sin_family = AF_INET;
  sw.sin_addr.s_addr = INADDR_ANY; // setting properly destination ip address
  sw.sin_port = htons(port);              // set destination port

  if(bind(server_socket, (struct sockaddr *)&sw, sizeof(struct sockaddr)) < 0 )
  {
    perror("CONNERR: socket");
    exit(EXIT_FAILURE);
  }
  serve(server_socket);
}

/*
* convert binary ip address to string
*/
char * ip_to_str(struct in_addr * addr){
  char * buf = NULL;
  buf = (char *) malloc(INET_ADDRSTRLEN);
  if (buf == NULL) {
    perror("Memmory alocation failure");
  }
  if (inet_ntop(AF_INET, addr, buf, INET6_ADDRSTRLEN) == NULL) {
           perror("inet_ntop");
           free(buf);
           exit(EXIT_FAILURE);
  }
  return buf;
}

/*
* check ip validity via inet_pton adn convert to binary ip
*/
uint32_t str_to_ip(const char * addr){

  struct in_addr *buf = NULL;
  buf = (struct in_addr *) malloc(sizeof(struct in_addr));
  if (buf == NULL) {
    perror("Memmory alocation failure");
  }
  if ((inet_pton(AF_INET, addr, buf)) != 1) {
    fprintf(stderr, "One of entered ip addresses is not valid \n");
    free(buf);
    exit(EXIT_FAILURE);
  }
  uint32_t tmp = buf->s_addr;
  free(buf);
  return tmp;
}

/**
* len length of ip address range, also check for right format
* @return index of / in range string
*/
int get_addr_len(char * addr){
  for (unsigned int i = 0; i < strlen(addr) ; i++) {
    if (addr[i] == '/') {
      return i;
    }
  }
  fprintf(stderr, "Specify network mask via cidr\n");
  exit(EXIT_FAILURE);
}

void parse_reserved(char * list) {
  int tmp = 0;
  int len = strlen(list);
  char buf[16];

  for (int i = 0; i < len ; i++) {
    if (list[i] == ',' ){
      bzero(buf, sizeof(buf));
      strncpy(buf, &list[tmp] , i-tmp);
      tmp = i + 1;
      r->restricted.push_back(str_to_ip(buf));
    }
    else if(i == len - 1){
      bzero(buf, sizeof(buf));
      strncpy(buf, &list[tmp] , i-tmp+1);
      r->restricted.push_back(str_to_ip(buf));
    }
  }
}

char * uint32_t_to_str(uint32_t ip) {
    struct in_addr ip_addr;
    ip_addr.s_addr = ip;
    return inet_ntoa(ip_addr);
}

uint32_t increment_ip_address(uint32_t add){
  return htonl(htonl(add)+1);
}

/*
* check arguments from stdin
*/
void check_args(int argc, char **argv)
{
  if (argc == 2  && (strcmp(argv[1],"--help") == 0))  {
    help();
    exit(EXIT_SUCCESS);
  }
  if (argc >= 3 && (strcmp(argv[1],"-p") == 0)) {

    int addr_len = get_addr_len(argv[2]);
    int prefix_len = strlen(argv[2]) - addr_len;

    char * addr = NULL;
    addr = (char *)(malloc(addr_len + 1));
    if ( addr == NULL) {
      perror("Count not allocate memmory");
    }
    char * prefix = NULL;
    prefix = (char *)(malloc(prefix_len));
    if ( prefix == NULL) {
      perror("Count not allocate memmory");
    }
    //printf("Len: %d\tPref:%d\n",addr_len, prefix_len );

    memcpy(addr, argv[2], addr_len);
    memcpy(prefix, &argv[2][addr_len +1] , prefix_len);
    // printf("Prf: %s\n",prefix );
    // printf("add %s\n",addr );

    r->cidr = check_num_args(prefix);
    if (r->cidr <= 0 || r->cidr == 31 || r->cidr >= 32) {
      fprintf(stderr, "Cannot operate with given CIDR range \n");
      exit(EXIT_FAILURE);
    }
    r->network = str_to_ip(addr);
    //printf("%u\n", r->network->s_addr );

    int test_range = 0;
    test_range = r->network >> r->cidr;
    if (test_range != 0) {
      fprintf(stderr, "Provided range is not valid.\n" );
      exit(EXIT_FAILURE);
    }
    //printf("%u\n",r->server_address );

    string b_ip = "255.255.255.255";
    const char * cb_ip = b_ip.c_str();

    uint32_t broadcast  = 0;
    broadcast = str_to_ip(cb_ip);
    broadcast = broadcast >> r->cidr; //switch right
    broadcast = ntohl(broadcast);     // convert byte order
    broadcast = ~broadcast;           //invert
    r->mask = broadcast;

    broadcast = ~broadcast;
    broadcast = r->network | broadcast;
    r->broadcast = broadcast;

    free(addr);
    free(prefix);

    if (argc == 4) {
      fprintf(stderr, "Missing list of ip address\n" );
      exit(EXIT_FAILURE);
    }
    if ((argc >= 5  && (strcmp(argv[3],"-e") == 0))) {
      parse_reserved(argv[4]);
    }
  }
  else{
    perror("Unrecognized arguments\n");
    exit(EXIT_FAILURE);
  }
}

void init_range(){
  r->next_usable = increment_ip_address(r->network);

  uint32_t tmp = r->next_usable;
  while (tmp != r->broadcast) {

    r->pool.push_back(tmp);
    tmp = increment_ip_address(tmp);
  }

  for (auto & element : r->restricted) {      // get rid of restricted addresses
    r->pool.erase(remove(r->pool.begin(), r->pool.end(), element), r->pool.end());
  }
  r->server_address = r->pool.front();
  r->pool.erase(r->pool.begin());
  r->next_usable = r->pool.front();
  r->pool.erase(r->pool.begin());
}
// ./dserver -p 192.168.0.0/24  [-e 192.168.0.1,192.168.0.2]
/** TODO -e
* MAIN
*/
int main(int argc, char *argv[]){

  signal(SIGINT, destroy);

  r = init();
  check_args(argc, argv);
  init_range();
  debug_range(r);

  init_server(67);
}
