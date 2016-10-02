/**
* Project: DHCP server created for ISA course at fit.vutbr.cz
* Author:  Martin Krajnak
* Mail:   xkrajn02@stud.fit.vutbr.cz
* Date:   2.10.2016
*/
#include "dserver.h"
using namespace std;

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
* Listen for new connections handle errors
*/
void listen_wrapper(int server_socket)
{
  if ((listen(server_socket, 1)) < 0) // listen for incomming connection
  {
    perror("ERROR: listen");
    exit(EXIT_FAILURE);
  }
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

/*
* Will return new socket for serving new client
*/
int get_new_client(int server_socket)
{
  struct sockaddr_in client;              //new client address
  socklen_t client_len = sizeof(client);  //size
  return accept(server_socket, (struct sockaddr*)&client, &client_len);
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
string get_regex_match(char *haystack,char * rgx_string)
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
void serve(int client_socket)
{
  char buffer[1024];
  while((recv(client_socket, buffer, 1023,0)) > 0)//handle message
  {
    string received = string (buffer);  //conversion to string

    if (received.find("DISCOVER") != string::npos) //Requested upload
      printf("DISCOVER\n" );
    else if ( received.find("OFFER") != string::npos )  //Requested download
      printf("OFFER\n" );
    else
    send_msg(client_socket,(char *)"ERR");//Message not recognized ERR
    memset(buffer, 0, 1024);
  }
  //printf("Connection closed\n");
}

/**
*   Handles communication between server and client
*/
void handle_communication(int server_socket)
{
  //cout<< "Hello server" << endl;
  listen_wrapper(server_socket);

  while(1)
  {
    int client_socket = get_new_client(server_socket);
		{
      int pid = fork_handler();
      if (pid == 0){ //handle new connection inside new process
        serve(client_socket);
        close(client_socket);
        exit(0);
      }
      else{
        close(client_socket);
      }
         //parent
		}
	}
}

/**
* Try to get socket
*/
int get_socket()
{
  int server_socket = 0;
  if((server_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0)  // creating socket
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

  //bind network socket to socket file descriptor
  int connection = 0;
  if((connection = bind (server_socket, (struct sockaddr *)&sw, sizeof(struct sockaddr))) < 0 )
  {
    perror("CONNERR: socket");
    exit(EXIT_FAILURE);
  }
  handle_communication(server_socket);
}

/** TODO all args
* MAIN
*/
int main(int argc, char const *argv[])
{
  if (argc == 2  && (strcmp(argv[1],"--help") == 0))  {
    help();
    exit(EXIT_SUCCESS);
  }

  init_server((int)strtod(argv[2],NULL));
  exit(0);
}
