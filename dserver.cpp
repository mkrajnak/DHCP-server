/**
* Project: DHCP server created for ISA course at fit.vutbr.cz
* Author:  Martin Krajnak
* Mail:   xkrajn02@stud.fit.vutbr.cz
* Date:   2.10.2016
*/
#include "dserver.h"
using namespace std;

struct lease_item{
  string mac_addr;
  uint32_t ip_addr;
  time_t lease_end;
}lease_item;

struct range{
  uint32_t network;                 // address range from stdin
  int cidr;                         // prefix
  uint32_t server_address;          // server ip address
  uint32_t next_usable;             // first_usable ip address from diven range
  uint32_t mask;                    // network_mask
  uint32_t broadcast;               // broadcast
  vector <uint32_t> restricted;
  vector <uint32_t> pool;
  vector <struct lease_item> leased_list;
}range;

/**
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

/**
* dealloc the struct when signal received
*/
void destroy(int sig){
  free(r);
  signal(sig, SIG_IGN);
  exit(EXIT_SUCCESS);
}

/**
* funcktion purly for debugging purposses
*/
void debug_range(struct range *r){
  printf("Address: %s/%d\n", uint32_t_to_str(r->network), r->cidr);
  printf("My address: %s\n", uint32_t_to_str(r->server_address));
  printf("Whos next?: %s\n", uint32_t_to_str(r->next_usable));
  printf("Mask: %s\n", uint32_t_to_str(r->mask));
  printf("Broadcast: %s\n", uint32_t_to_str(r->broadcast));

  std::cout << "Restricted" << std::endl;
  for (auto & element : r->restricted) {
    cout  << uint32_t_to_str(element) << endl;
  }

  std::cout << "Pool" << std::endl;
  for (auto & element : r->pool) {
    cout  << uint32_t_to_str(element) << endl;
  }
  std::cout << "Leases" << std::endl;
  for (auto & element : r->leased_list) {
    cout << element.mac_addr << " "<< uint32_t_to_str(element.ip_addr) << " "<< element.lease_end << endl;
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
        "\t -s <filename> are static leases those ip addresses will be available only for specific client\n"
        "be provided to clients, separated by comma \n"
      );
}

/**
* Send broad cast message
*/
void send_msg(unsigned char * buffer, const char * sendto_addr){
  int fd;                                 // UDP socket
  struct sockaddr_in addr;                // address data structure

  if ((fd=socket(AF_INET,SOCK_DGRAM,0)) < 0) // create a UDP socket for broadcast
    perror("Socket() failed");

  memset(&addr,0,sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_addr.s_addr=inet_addr(sendto_addr); // set the broadcast address
  addr.sin_port=htons(68);

  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    perror("socket failed()");
  int on = 1;
  // set socket to send broadcast messages, but only if broadcast is present
  if (strcmp(sendto_addr, BROADCAST) == 0) {
    if ((setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on))) == -1)
      perror("setsockopt failed()");
  }

  if (sendto(fd,buffer, BUFSIZE,0,(struct sockaddr *) &addr, sizeof(addr)) < 0) // send data without EOL
    perror("sendto");

  if ((close(fd)) == -1)
    perror("close() failed");
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
    lease_expiration_check();
    switch (buffer[242]) {
      case (int) DHCP_DISCOVER:
        send_offer(buffer);
        break;
      case (int) DHCP_REQUEST:
        send_ack(buffer);
        break;
      case (int) DHCP_RELEASE:
        release(buffer);
        break;
      default: break;
    }
    bzero(buffer,sizeof(buffer));
  }
  close(srv_socket);
}

/*
* go through leases and delete expired leases, give adress back to pool
*/
void lease_expiration_check(){
    time_t t;
    time(&t);
    if (r->leased_list.empty()) {
      return;
    }
    vector<struct lease_item>::iterator it = r->leased_list.begin();
    while(it != r->leased_list.end()) {
      if (it->lease_end == -1) {
        ++it;
        continue;
      }
      double seconds = difftime(t, it->lease_end);
      if (seconds > 0){
        debug_range(r);
        uint32_t tmp = it->ip_addr;
        r->pool.push_back(tmp);   // address back to pool
        it = r->leased_list.erase(it);    // delete from lease list
      }
      else
        ++it;
    }
}

/*
* prepare buffer for offer message, check requested address and send it if possible
*/
void send_offer(unsigned char * buffer){
  //debug_discover(buffer);
  prepare_offer(buffer);
  char chaddr_str[18];
  get_client_mac_address(buffer, chaddr_str);

  uint32_t ip = 0;
  ip = check_client_leases(chaddr_str);
  if (ip) {
    lease(ip, chaddr_str, 0);
    rewrite_ip_address(&buffer[16], ip);  //write ip to buffer
    send_msg(buffer, BROADCAST);
    return;
  }
  else if (r->next_usable == 0) {
    send_nak(buffer);
  }
  else {
    lease(r->next_usable, chaddr_str, 0);
    rewrite_ip_address(&buffer[16], r->next_usable);  //write ip to buffer
    send_msg(buffer, BROADCAST);
  }

  if (!r->pool.empty()) {
    r->next_usable = r->pool.front();
    r->pool.erase(r->pool.begin());
  }
  else
    r->next_usable = 0;
}

/*
* send ack message, determine if user is requesting renew
*/
void send_ack(unsigned char *buffer){
  char chaddr_str[18];
  char ip_str[16];
  get_requested_ip_address(buffer, ip_str);
  get_client_mac_address(buffer, chaddr_str);

  prepare_offer(buffer);

  buffer[242] = (int) DHCP_ACK;  //ack
  uint32_t renew = 0;
  renew = check_client_leases(chaddr_str);
  if (ip_str != NULL) {
    renew = str_to_ip(ip_str);
  }
  if (!renew) {                         // get ip from pool
    //std::cout << "New client" << std::endl;

    vector<uint32_t>::iterator it = r->pool.begin();
    while(it != r->pool.end()){     // check if we have desired ip in pool
      if (*it == renew) {
        it = r->pool.erase(it);     // delete address from pool
        lease(renew, chaddr_str, 1);
        rewrite_ip_address(&buffer[16], renew);          //write ip to buffer
        send_msg(buffer, BROADCAST);
        return;
      }
      else
          ++it;
    }
    send_nak(buffer);
  }
  else {                                    // found bounded client
    lease(renew, chaddr_str, 1);
    rewrite_ip_address(&buffer[16], renew);          //write ip to buffer
    send_msg(buffer, BROADCAST);
  }
}
/*
* simply set the NAK flag and seng message out
*/
void send_nak(unsigned char *buffer){
  buffer[242] = (int) DHCP_NAK;  //nack
  send_msg(buffer, BROADCAST);
}

/*
*  delete address lease, add address to pool
*/
void release(unsigned char * buffer){
  char chaddr_str[18];
  get_client_mac_address(buffer, chaddr_str);
  uint32_t add_to_release = check_client_leases(chaddr_str);
  time_t t = get_lease_time(chaddr_str);
  if (t == -1) {  //do not add to pool of addresses
    return;
  }
  if (add_to_release)
    r->pool.push_back(add_to_release);
}

/**
*  rewrite ip address in desired part of buffer
*/
void rewrite_ip_address(unsigned char *buffer, uint32_t ip){
  for (int i = 0; i < 4; i++) {
    buffer[i] = (ip >> (i*8)) & 0xFF;
  }
}

/**
*  parse address which client requests
*/
void get_requested_ip_address(unsigned char * buffer, char * str){
  for (int i = 240; i < 512; i++) {
    if ((int)buffer[i] == 50 && (int)buffer[i+1] == 4) {
      unsigned char chaddr[4];
      memcpy(chaddr, &buffer[i+2], 4);
      sprintf(str, "%d.%d.%d.%d",chaddr[0], chaddr[1], chaddr[2], chaddr[3]);
      str[16]='\0';
      return;
    }
  }
  str = NULL;
}

/**
* Parse client mac address from packet
*/
void get_client_mac_address(unsigned char * buffer, char * str)
{
  unsigned char chaddr[6];
  memcpy(chaddr, &buffer[28], 6);

  sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",chaddr[0],
        chaddr[1], chaddr[2], chaddr[3], chaddr[4],chaddr[5]);
  str[18]='\0';
}


/**
* bind client ip address mac address and lease end time
* store it
*/
void lease(uint32_t addr, char * chaddr_str, int print){//2016-09-29_13:45
  time_t rawtime;
  struct tm * timeinfo;
  char ct_buffer[20];      // current time buffer
  char le_buffer[20];      // lease end

  time (&rawtime);
  timeinfo = localtime (&rawtime);
  strftime (ct_buffer,20,"%F_%R",timeinfo);

  timeinfo->tm_hour +=1;
  strftime (le_buffer,20,"%F_%R",timeinfo);

  struct lease_item item;   // write to lease list
  item.mac_addr = (string) chaddr_str;
  item.ip_addr = addr;
  item.lease_end = mktime(timeinfo);
  r->leased_list.insert(r->leased_list.begin(), item);

  if (print) {
    printf("%s %s %s %s\n", chaddr_str, uint32_t_to_str(addr), ct_buffer, le_buffer);
  }
}

/*
* return ip address which is leased to client with chaddr_str
*/
uint32_t check_client_leases(char * chaddr_str){
  if (r->leased_list.empty()) {         // check if eny leases are documented
    return 0;
  }
  uint32_t tmp_addr = 0;
  unsigned int tmp_index = r->leased_list.size();
  for(size_t i = 0; i != r->leased_list.size(); i++) {
    if (r->leased_list[i].mac_addr == (string) chaddr_str) {
      tmp_addr = r->leased_list[i].ip_addr;   // if lease for client with chaddr
      if (r->leased_list[i].lease_end == -1) {
        return tmp_addr;                      // reserved addr do not deleted
      }
      tmp_index = i;                          // is found remember its address
      break;                                  // and index
    }
  }
  if (tmp_index != r->leased_list.size()) {   // remove the record because we will make new one
    r->leased_list.erase(r->leased_list.begin() + tmp_index);
  }
  return tmp_addr;
}

/*
* return client lease time
*/
time_t get_lease_time(char * chaddr_str){
  if (r->leased_list.empty()) {         // check if eny leases are documented
    return 0;
  }
  for(size_t i = 0; i != r->leased_list.size(); i++) {
    if (r->leased_list[i].mac_addr == (string) chaddr_str) {
      return r->leased_list[i].lease_end;   // if lease for client with chaddr
    }
  }
  return 0;
}

/*
* prepare content of buffer to offer
*/
void prepare_offer(unsigned char * buffer)
{
  rewrite_ip_address(&buffer[16], r->next_usable);
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
}


/**
* receive and parse dhcp packet
*/
void debug_discover(unsigned char * buffer){

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
    return 0;
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

/*
* simply convert string to ip address, inet_ntoa provides error corection
*/
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
    memcpy(addr, argv[2], addr_len);
    memcpy(prefix, &argv[2][addr_len +1] , prefix_len);

    r->cidr = check_num_args(prefix);
    if (r->cidr <= 0 || r->cidr == 31 || r->cidr >= 32) {
      fprintf(stderr, "Cannot operate with given CIDR range \n");
      exit(EXIT_FAILURE);
    }
    r->network = str_to_ip(addr);

    int test_range = 0;
    test_range = r->network >> r->cidr;
    if (test_range != 0) {
      fprintf(stderr, "Provided range is not valid.\n" );
      exit(EXIT_FAILURE);
    }

    uint32_t broadcast  = 0;
    broadcast = str_to_ip(BROADCAST);
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
    else if (argc == 5 && strcmp(argv[3], "-s")== 0) {
      FILE *f;
      f = fopen(argv[4], "r");
      if (f == NULL) {
        fprintf(stderr, "Cannot open file\n" );
        exit(EXIT_FAILURE);
      }
      char temp[1024];
      char *tok;
      string mac = "";
      string ip = "";
      while (fgets (temp, 1024, f) !=0 ){        //reading line from file
             tok = strtok(temp," ");            //stripping first value from line
             int col = 0;
             while(tok!=NULL){
               for (unsigned int i = 0; i < sizeof(tok); i++) {
                 if (isspace((int)tok[i])) {  // empty line bye bye
                   return;
                 }
               }
               if (col > 1) { // more than one column in file
                 fprintf(stderr, "Wrong static file format\n");
                 exit(EXIT_FAILURE);
               }
               else if (col == 1){
                 ip = (string) tok;
                 ip.erase(std::remove(ip.begin(), ip.end(), '\n'), ip.end());
               }
               else{
                 mac = (string) tok;
                 if (mac.length() == 16) { // just for sure
                   fprintf(stderr, "Wrong static file format(mac address)\n");
                   exit(EXIT_FAILURE);
                 }
               }
               tok = strtok(NULL," ");
               col++;
            }
            struct lease_item item;   // write to lease list
            item.mac_addr = mac;
            item.ip_addr = str_to_ip(ip.c_str());
            item.lease_end = -1;      //iset to nfinity
            r->leased_list.insert(r->leased_list.begin(), item);  //permanently add lease item
            r->restricted.push_back(item.ip_addr);  //add address to restricted
      }
      fclose(f);
  }
}
  else{
    perror("Unrecognized arguments\n");
    exit(EXIT_FAILURE);
  }
}

/*
*  initiate the range of ip addresses, broadcast, router ip and other
*/
void init_range(){
  // first usable is network address +1
  r->next_usable = increment_ip_address(r->network);

  uint32_t tmp = r->next_usable;
  while (tmp != r->broadcast) {   // add all valid ip addresses to pool
    r->pool.push_back(tmp);
    tmp = increment_ip_address(tmp);
  }
  if (!r->restricted.empty()) {
    for (auto & element : r->restricted) {     // get rid of restricted addresses
      if(find(r->pool.begin(), r->pool.end(), element) != r->pool.end()) {
        r->pool.erase(remove(r->pool.begin(), r->pool.end(), element));
      }
    }
  }
  r->server_address = r->pool.front();      // assign fisr available to server
  r->pool.erase(remove(r->pool.begin(), r->pool.end(), r->server_address));
  if (r->pool.empty()) {
    fprintf(stderr, "ERR: No free ip addresses from given params\n");
    free(r);
    exit(EXIT_FAILURE);
  }
  r->next_usable = r->pool.front();       // prepare next one for hosts
  r->pool.erase(remove(r->pool.begin(), r->pool.end(), r->next_usable));
}

/**
* MAIN
*/
int main(int argc, char *argv[]){
  signal(SIGINT, destroy);
  r = init();
  check_args(argc, argv);
  init_range();
  //debug_range(r);
  init_server(DHCPSERVERPORT);
  return 0;
}
