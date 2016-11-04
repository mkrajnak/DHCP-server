/**
* Project: DHCP server created for ISA course at fit.vutbr.cz
* Author:  Martin Krajnak
* Mail:   xkrajn02@stud.fit.vutbr.cz
* Date:   2.10.2016
*/
#include "dserver.h"
using namespace std;


struct range{
  struct in_addr * address;         // address range from stdin
  int cidr;               // prefix
  char * server_address;  // server ip address
  char * first_usable;    // first_usable ip address from diven range
  char * mask;            // network_mask
  char * broadcast;            // broadcast
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
  r->address = NULL;
  r->cidr = 0;
  r->server_address = NULL;
  r->first_usable = NULL;
  r->mask = NULL;
  r->broadcast = NULL;
  return r;
}

void destroy(struct range *r){
  free(r->address);
  free(r->server_address);
  free(r->first_usable);
  free(r->broadcast);
  free(r->mask);
  free(r);
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

    handle_discover(rcvd, buffer);

    prepare_offer(buffer);

    send_msg(buffer);
    memset( buffer, 0 ,sizeof(buffer));
  }
  close(srv_socket);
}

void prepare_offer(unsigned char * buffer)
{
  unsigned char yaddr[4];
  yaddr[0] = (int) 192;
  yaddr[1] = (int) 168;
  yaddr[2] = (int) 0;
  yaddr[3] = (int) 150;
  memcpy(&buffer[16], yaddr, 4);
  debug_field_int("yaddr :", yaddr, sizeof(yaddr));

  unsigned char siaddr[4];
  siaddr[0] = (int) 192;
  siaddr[1] = (int) 168;
  siaddr[2] = (int) 0;
  siaddr[3] = (int) 1;

  memcpy(siaddr, &buffer[20], 4);
  debug_field_int("siaddr :", siaddr, sizeof(siaddr));

  buffer[0] = (int) 2;
  buffer[242] = (int) 2;

  buffer[243] = (int) 1;
  buffer[244] = (int) 4;

  buffer[245] = (int) 255;
  buffer[246] = (int) 255;
  buffer[247] = (int) 255;
  buffer[248] = (int) 0;

  buffer[249] = (int) 54;
  buffer[250] = (int) 4;

  buffer[251] = (int) 192;
  buffer[252] = (int) 168;
  buffer[253] = (int) 1;
  buffer[254] = (int) 63;

  buffer[255] = (int) 255;

  bzero(&buffer[256],511-255);
  debug_buffer(buffer, 512);
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

  debug_buffer(buffer, rcvd);

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
struct in_addr * str_to_ip(const char * addr){
  struct in_addr * buf = NULL;
  buf = (struct in_addr *) malloc(sizeof(struct in_addr));
  if (buf == NULL) {
    perror("Memmory alocation failure");
  }
  if ((inet_pton(AF_INET, addr, buf)) != 1) {
    fprintf(stderr, "Entered ip address is not valid \n");
    free(buf);
    exit(EXIT_FAILURE);
  }
  return buf;
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
  printf("%s\n",list );
  int tmp = 0;
  unsigned int len = strlen(list);
  for (unsigned int i = 0; i < len ; i++) {
    if (list[i] == ',' || i == len - 1){
      char * buf = NULL;
      buf = (char *) malloc(sizeof(struct in_addr));
      if (buf == NULL) {
        perror("Memmory alocation failure");
      }
      strncpy(buf, &list[tmp] , i);
      tmp = i + 1;
      printf("%s\n",buf );
    }
  }
}

/*
* check arguments from stdin
*/
void check_args(int argc, char **argv, struct range *r)
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
    printf("Len: %d\tPref:%d\n",addr_len, prefix_len );

    memcpy(addr, argv[2], addr_len);
    memcpy(prefix, &argv[2][addr_len +1] , prefix_len);
    printf("Prf: %s\n",prefix );

    r->cidr = check_num_args(prefix);
    if (r->cidr <= 0 || r->cidr == 31 || r->cidr >= 32) {
      fprintf(stderr, "Cannot operate with given CIDR range \n");
      exit(EXIT_FAILURE);
    }
    r->address = str_to_ip(addr);

    int test_range = 0;
    test_range = r->address->s_addr >> r->cidr;
    if (test_range != 0) {
      fprintf(stderr, "Provided range is not valid.\n" );
      exit(EXIT_FAILURE);
    }

    printf("%u\n", r->address->s_addr);
    //printf("%s\n", ip_to_str(r->address));
    printf("%d\n", r->cidr );

    string b_ip = "255.255.255.255";
    const char * cb_ip = b_ip.c_str();

    struct in_addr * broadcast  = NULL;
    broadcast = str_to_ip(cb_ip);
    //printf("%s\n", ip_to_str(broadcast));
    broadcast->s_addr = broadcast->s_addr >> r->cidr; //switch right
    //printf("%s\n", ip_to_str(broadcast));
    broadcast->s_addr = ntohl(broadcast->s_addr);     // convert byte order
    //printf("%s\n", ip_to_str(broadcast));
    broadcast->s_addr = ~broadcast->s_addr;           //invert
    r->mask = ip_to_str(broadcast);
    //printf("Mask: %s\n", r->mask);

    broadcast->s_addr = ~broadcast->s_addr;
    broadcast->s_addr = r->address->s_addr | broadcast->s_addr;
    r->broadcast = ip_to_str(broadcast);
    printf("%s\n", r->broadcast);

    free(broadcast);
    free(addr);
    free(prefix);

    if (argc == 4) {
      fprintf(stderr, "Missing list of ip address\n" );
      exit(EXIT_FAILURE);
    }
    // if ((argc >= 5  && (strcmp(argv[3],"-e") == 0))) {
    //   parse_reserved(argv[4]);
    // }
  }
  else{
    perror("Unrecognized arguments\n");
    exit(EXIT_FAILURE);
  }


  // ./dserver -p 192.168.0.0/24  [-e 192.168.0.1,192.168.0.2]
  /** TODO -e
  * MAIN
  */
}
int main(int argc, char *argv[]){

  string hello = "hey";
  cout << hello << endl;

  struct range *r = init();
  check_args(argc, argv, r);

  destroy(r);
  init_server(67);
  exit(EXIT_SUCCESS);
}
