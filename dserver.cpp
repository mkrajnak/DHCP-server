/**
* Project: DHCP server created for ISA course at fit.vutbr.cz
* Author:  Martin Krajnak
* Mail:   xkrajn02@stud.fit.vutbr.cz
* Date:   2.10.2016
*/
#include "dserver.h"
using namespace std;


struct range{
  unsigned char * address;         // address range from stdin
  int cidr;               // prefix
  unsigned char * server_address;  // server ip address
  unsigned char * first_usable;    // first_usable ip address from diven range
  unsigned char * mask;            // network_mask
  unsigned char * broadcast;            // broadcast
}range;

/**
* Parsing numeric values + error detection
*/
int check_num_args(char *arg)
{
   	char *white;
   	int num = (int)strtod(arg,&white);
   	if(strlen(white) != 0)
   	{
     	fprintf(stderr,"Unexpected input \"%s\"\n",white);
     	exit(EXIT_FAILURE);
   	}
   	else
   	  return num;   //no char detected, numeric value is returned
}

/*
* INIT struct
*/
struct range * init(){
  struct range * r =(struct range *) malloc(sizeof(struct range));
  if (r == NULL) {
    perror("could not allocate memmory");
  }
  r->address = NULL;
  r->cidr = 0;
  r->server_address = NULL;
  r->first_usable = NULL;
  r->mask = NULL;
  return r;
}
/**
* HELP
*/
void help()
{
  printf("DHCP server implemented by Martin Krajnak <xkrajn02@stud.fit.vutbr.cz>:\n"
        "Usage:\t ./dserver -p 192.168.0.0/24 [-e 192.168.0.1,192.168.0.2]\n"
        "\t\t./dserver -p 192.168.0.0/24 -s static.txt\n"
        "\t -p <ip_address/mask> ip addess range\n"
        "\t -e <ip_address/mask> reserved ip addresses which are not allowed to\n"
        "be provided to clients, separated by comma \n"
      );
}

/**
* Try to fork and handle errors
*/
int fork_handler()
{
  int pid;
  if((pid = fork()) < 0)  //Try to create new process
  {
    perror("FORKERR");
    exit(EXIT_FAILURE);
  }
  return pid;
}

/**
* Send message
*/
void send_msg(int socket, char *msg)
{
  int sended = send(socket, msg, strlen(msg), 0);
  if (sended < 0)
    perror("SENDERR");
}

/**
* Function return first match achieved rgx_string
*/
string get_regex_match(char *haystack, char * rgx_string)
{
  cmatch match;         //store matches
  regex rgx(rgx_string);//create and compile regex
  if (!(regex_search(haystack, match, rgx))) {//try to find
    fprintf(stderr, "FATALERR: Message unmatched\n" );
    exit(EXIT_FAILURE);
  }
  return match.str(1);
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
    printf("Request received from %s, port %d\n",inet_ntoa(client.sin_addr),ntohs(client.sin_port));
    printf("Message:\n");// \"%d\":end\n", buffer[0]);

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
    printf("Xid: 0x");
    for (int i = 0; i < 4; i++) {
      printf("%02x", xid[i]);
    }
    printf("\n");

    unsigned char secs[2];
    memcpy(secs, &buffer[8], 2);
    for (int i = 0; i < 2; i++) {
      printf("%02x", secs[i]);
    }
    printf("\n");

    unsigned char flags[2];
    memcpy(flags, &buffer[10], 2);
    for (int i = 0; i < 2; i++) {
      printf("%02x", flags[i]);
    }
    printf("\n");

    unsigned char ciadr[4];
    memcpy(ciadr, &buffer[12], 4);
    printf("ciadr: ");
    for (int i = 0; i < 4; i++) {
      printf("%d.", ciadr[i]);
    }
    printf("\n");

    unsigned char yaddr[4];
    memcpy(yaddr, &buffer[16], 4);
    printf("yaddr: ");
    for (int i = 0; i < 4; i++) {
      printf("%d.",yaddr[i]);
    }
    printf("\n");

    unsigned char siaddr[4];
    memcpy(siaddr, &buffer[20], 4);
    printf("siaddr: ");
    for (int i = 0; i < 4; i++) {
      printf("%d.",siaddr[i]);
    }
    printf("\n");

    unsigned char giaddr[4];
    memcpy(giaddr, &buffer[24], 4);
    printf("giaddr: ");
    for (int i = 0; i < 4; i++) {
      printf("%d.",giaddr[i]);
    }
    printf("\n");

    unsigned char chaddr[16];
    memcpy(chaddr, &buffer[28], 16);
    printf("chaddr: 0x");
    for (int i = 0; i < 16; i++) {
      printf("%02x.",chaddr[i]);
    }
    printf("\n");

    unsigned char sname[64];
    memcpy(sname, &buffer[44], 64);
    printf("sname: ");
    for (int i = 0; i < 64; i++) {
      printf("%c",sname[i]);
    }
    printf("\n");

    unsigned char magic_cookie[4];
    memcpy(sname, &buffer[236], 4);
    printf("magic_cookie: ");
    for (int i = 0; i < 4; i++) {
      printf("%02x",magic_cookie[i]);
    }
    printf("\n");

    //unsigned char msg_type[4];    //option 53
    memcpy(sname, &buffer[240], 3);
    printf("magic_cookie: ");
    for (int i = 0; i < 4; i++) {
      printf("%02x",magic_cookie[i]);
    }
    printf("\n");

    printf("ID \t|INT\t|CHAR\t|HEX\t|\n");
    for (int i = 0; i < rcvd; i++) {
      printf(" %4d| %4d\t| %4c\t| %02x\t\n",i , buffer[i], buffer[i], buffer[i]);
    }
    printf("--------------END----------\n");

    if (strncmp((char*)buffer,"END.",4) == 0){    // "END." string exits application
    	printf("closing socket\n");
    	close(srv_socket);
    	exit(0);
    }
    memset( buffer, 0 ,sizeof(buffer));
  }
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

  if(bind (server_socket, (struct sockaddr *)&sw, sizeof(struct sockaddr)) < 0 )
  {
    perror("CONNERR: socket");
    exit(EXIT_FAILURE);
  }
  serve(server_socket);
}
/*
* check ip validity via inet_pton adn convert to binary ip
*/
unsigned char * str_to_ip(char * addr){
  unsigned char * buf = (unsigned char *) malloc(sizeof(struct in_addr));
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

/*
* convert binary ip address to string
*/
char * ip_to_str(unsigned char * addr){
  char * buf = (char *) malloc(sizeof(struct in_addr));
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

/*
* check arguments from stdin
*/
void check_args(int argc, char **argv, struct range *r)
{
  if (argc == 2  && (strcmp(argv[1],"--help") == 0))  {
    help();
    exit(EXIT_SUCCESS);
  }
  else if (argc == 3 && (strcmp(argv[1],"-p") == 0)) {

    int addr_len = get_addr_len(argv[2]);
    char * addr = (char *) malloc(addr_len+1);
    if ( addr == NULL) {
      perror("Count not allocate memmory");
    }
    char prefix[2];
    strncpy(addr, argv[2], addr_len);
    strncpy(prefix, argv[2] + addr_len+1, 2);
    r->cidr = check_num_args(prefix);
    if (r->cidr <= 0 || r->cidr == 31 || r->cidr >= 32) {
      fprintf(stderr, "Cannot operate with given CIDR range \n");
      exit(EXIT_FAILURE);
    }
    r->address = str_to_ip(addr);

    printf("%s\n", ip_to_str(r->address));
    printf("%d\n", r->cidr );

    // unsigned int broadcast = UINT_MAX;
    // printf("MAX: %u\n",broadcast );
    // broadcast = broadcast << r->cidr;
    // printf("%u\n",broadcast );
    // broadcast = ~ broadcast ;
    // printf("%s\n",r->address );
    // *(r->address) = *(r->address) | broadcast;
    // printf("%s\n",r->address );
    //
    // printf("%s\n", ip_to_str(r->address) );


    // r->broadcast = (unsigned char *) malloc(sizeof(struct in_addr));
    // if (r->broadcast == NULL) {
    //   perror("Memmory alocation failure");
    // }
    // *r->broadcast = htons(*r->address) + broadcast;

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

  struct range *r = init();
  check_args(argc, argv, r);

  free(r->address);
  free(r);
  //init_server(67);
  exit(EXIT_SUCCESS);
}
