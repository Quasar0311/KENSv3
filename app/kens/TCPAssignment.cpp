/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

#include <E/Networking/E_Host.hpp>

namespace E {

TCPAssignment::TCPAssignment(Host *host)
    : HostModule("TCP", host),
      NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      NetworkLog(host->getNetworkSystem()), TimerModule(host->getSystem()) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize()
{
  socketList = std::vector <Socket *>();
  listenList = std::vector <Socket *>();
  acceptList = std::vector <Socket *>();
  connect_lock_UUID = 0;
}

void TCPAssignment::finalize() {}

void TCPAssignment::PrintAllSockets(void)
{
  for (std::vector <Socket *>::iterator it = socketList.begin(); it != socketList.end(); it++)
  {
    std::cout << (*it)->socketUUID << " " 
              << (*it)->pid  << " " 
              << (*it)->fd  << " " 
              << (*it)->state << " ";
  }
}


Socket *TCPAssignment::getSocket(int pid, int fd) {
  std::vector <Socket *>::iterator it;
  for (it = socketList.begin(); it != socketList.end(); it++) {
    if ((*it) -> pid == pid && (*it) -> fd == fd) {
      return (*it);
    }
  }
  return NULL;
}

void TCPAssignment::eraseInsocketList(Socket *sock) {
  std::vector <Socket *>::iterator it;
  for (it = socketList.begin(); it != socketList.end();) {
    if ((*it) == sock) {
      // std::vector<myType *> erase() does not automatically destroies the instance.
      delete (*it)->addr_in;
      delete (*it)->addr_in_dest;
      for (auto p: (*it)->connection_queue)
      {
        delete p;
      }
      delete (*it);
      it = socketList.erase(it);
    }
    else {
      ++it;
    }
  }
}

Packet TCPAssignment::createPacket(Socket *sock, uint8_t flag) {
  Sockad_in *addr_from = sock -> addr_in;
  Sockad_in *addr_to = sock -> addr_in_dest;

  uint32_t addr_from_ip = htonl(addr_from -> sin_addr);
  uint32_t addr_to_ip = htonl(addr_to -> sin_addr);
  uint16_t addr_from_port = htons(addr_from -> sin_port);
  uint16_t addr_to_port = htons(addr_to -> sin_port);
  
  Packet pkt(54);
  
  // IPv4 Header Format
  // Offsets
  // 0	Version	IHL	DSCP	ECN	Total Length
  // 4	Identification	Flags	Fragment Offset
  // 8	Time To Live	Protocol	Header Checksum
  // 12	Source IP Address
  // 16	Destination IP Address
  pkt.writeData(14 + 12, &addr_from_ip, 4);
  pkt.writeData(14 + 16, &addr_to_ip, 4);

  // TCP Segment Header Format
  // Offsets
  // 0	Source port	Destination port
  // 4	Sequence number
  // 8	Acknowledgment number (if ACK set)
  // 12	Data offset	Reserved NS	CWR	ECE	URG	ACK	PSH	RST	SYN	FIN	Window Size
  // 16	Checksum	Urgent pointer (if URG set)
  pkt.writeData(34, &addr_from_port, 2);
  pkt.writeData(34 + 2, &addr_to_port, 2);

  uint32_t seq = sock -> seq_num;
  uint32_t ack = sock -> ack_num;

  pkt.writeData(34 + 4, &seq, 4);
  pkt.writeData(34 + 8, &ack, 4);

  uint8_t head_len = 80;
  pkt.writeData(34 + 12, &head_len, 1);
  pkt.writeData(34 + 13, &flag, 1);

  uint16_t window = htons(65535);
  pkt.writeData(34 + 14, &window, 2);

  uint8_t tcp_seg_buf[20];
  uint16_t checksum = NetworkUtil::tcp_sum(addr_from_ip, addr_to_ip, tcp_seg_buf, 20);
  checksum = htons(~checksum);
  pkt.writeData(34 + 16, &checksum, 2);

  return pkt;
}

// Process a packet inbound to sockfd
void TCPAssignment::processPacket (int sockfd, Packet &&packet)
{
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  uint32_t addr_from_ip;
  uint32_t addr_to_ip;
  uint16_t addr_from_port;
  uint16_t addr_to_port;
  
  uint32_t seq;
  uint32_t ack;
  uint8_t head_len;
  uint8_t flag;
  // uint16_t window;
  // uint16_t checksum;

  // TODO: validate a checksum first

  // IPv4 Header Format
  // Offsets
  // 0	Version	IHL	DSCP	ECN	Total Length
  // 4	Identification	Flags	Fragment Offset
  // 8	Time To Live	Protocol	Header Checksum
  // 12	Source IP Address
  // 16	Destination IP Address
  packet.readData(14 + 12, &addr_from_ip, 4);
  packet.readData(14 + 16, &addr_to_ip, 4);
  std::cout << "Packet Arrived: " << addr_from_ip << std::endl;

  // TCP Segment Header Format
  // Offsets
  // 0	Source port	Destination port
  // 4	Sequence number
  // 8	Acknowledgment number (if ACK set)
  // 12	Data offset	Reserved NS	CWR	ECE	URG	ACK	PSH	RST	SYN	FIN	Window Size
  // 16	Checksum	Urgent pointer (if URG set)
  packet.readData(34, &addr_from_port, 2);
  packet.readData(34 + 2, &addr_to_port, 2);

  packet.readData(34 + 4, &seq, 4);
  packet.readData(34 + 8, &ack, 4);
  packet.readData(34 + 12, &head_len, 1);
  packet.readData(34 + 13, &flag, 1);

  addr_from_ip = ntohl(addr_from_ip);
  addr_from_port = ntohs(addr_from_port);
  addr_to_ip = ntohl(addr_to_ip);
  addr_to_port = ntohs(addr_to_port);

  seq = ntohl(seq);
  ack = ntohl(ack);

  Socket *sock_found = NULL;

  std::vector <Socket *>::iterator it;
  for (it = listenList.begin(); it != listenList.end(); it++)
  {
    Socket *sock = *it;
    if ((sock->addr_in->sin_port == addr_to_port)
      && (sock->addr_in->sin_addr == addr_to_ip || sock->addr_in->sin_addr == htonl(INADDR_ANY)))
      {
        /* Destination ip:port == any listening socket ip:port */
        std::vector <std::pair <int, Socket *>>::iterator it_pair;
        for (it_pair = acceptList.begin(); it_pair != acceptList.end(); it_pair++)
        {
          if (it_pair->second)
          {
            returnSystemCall (it_pair->first, );
          }
        }
      }
  }

  // No accept waiting socket for this packet
  for (it = listenList.begin(); it != listenList.end(); it++)
  {
    Socket *sock = *it;
    if ((sock->addr_in->sin_port == addr_to_port)
      && (sock->addr_in->sin_addr == addr_to_ip || sock->addr_in->sin_addr == htonl(INADDR_ANY)))
    {
      sock->connection_queue.push_back ()
    }
  }

  if (sock_found == NULL) {
    std::cout << "Not found\n";
  }

  switch (sock_found -> state) {
    case SS_LISTEN:
      ;
    default:
      ;
  }
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  (void)syscallUUID;
  (void)pid;

  std::cout << "syscall: " << syscallUUID
            << " call number: " << param.syscallNumber << std::endl;
  getchar();
  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, param.param1_int,
    param.param2_int, param.param3_int);
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, param.param1_int);
    break;
  case READ:
    this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr,
    param.param3_int);
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr,
    param.param3_int);
    break;
  case CONNECT:
    this->syscall_connect(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr*>(param.param2_ptr),
    (socklen_t)param.param3_int);
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, param.param1_int,
    param.param2_int);
    break;
  case ACCEPT:
    this->syscall_accept(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr*>(param.param2_ptr),
    		static_cast<socklen_t*>(param.param3_ptr));
    break;
  case BIND:
    this->syscall_bind(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr *>(param.param2_ptr),
    		(socklen_t) param.param3_int);
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr *>(param.param2_ptr),
    		static_cast<socklen_t*>(param.param3_ptr));
    break;
  case GETPEERNAME:
    this->syscall_getpeername(syscallUUID, pid, param.param1_int,
    		static_cast<struct sockaddr *>(param.param2_ptr),
    		static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::syscall_socket (UUID syscallUUID, int pid, int domain, int type, int protocol)
{
  int fd;
  if ((fd = createFileDescriptor (pid)) == -1)
  {
    returnSystemCall (syscallUUID, -1);
  }
  Socket *newSocket = new Socket;
  newSocket->socketUUID = syscallUUID;
  newSocket->fd = fd;
  newSocket->pid = pid;
  newSocket->domain = domain;
  newSocket->type = type;
  newSocket->protocol = protocol;
  newSocket->addr_in = NULL;
  newSocket->addr_in_dest = NULL;
  newSocket->state = SS_FREE;
  newSocket->ack_num = 0;
  newSocket->seq_num = 0;
  newSocket->connection_queue = std::vector <Socket *>();

  socketList.push_back(newSocket);
  // PrintAllSockets();
  // getchar();
  this -> returnSystemCall (syscallUUID, fd);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) 
{
  Socket *sock = getSocket(pid, fd);
  if (sock == NULL) {
    returnSystemCall(syscallUUID, -1);
    return;
  }

  eraseInsocketList(sock);
  removeFileDescriptor(pid, fd);
  this -> returnSystemCall(syscallUUID, 1);
}

void TCPAssignment::syscall_read(UUID syscllUUID, int pid, 
                                 int param1, void *param2, int param3) 
{

}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, 
                                  int param1, void *param2, int param3) 
{
  
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, 
                                    int sockfd, struct sockaddr *addr, socklen_t addrlen) 
{
  Socket *sock = getSocket(pid, sockfd);
  // ipv4_t ip;
  Sockad_in *address_in_dest;
  
  if (sock == NULL) {
    this -> returnSystemCall(syscallUUID, -1);
    return;
  }
  
  address_in_dest = new Sockad_in;
  address_in_dest -> sin_family = AF_INET;
  address_in_dest -> sin_port = ntohs(((sockaddr_in *) addr) -> sin_port);
  address_in_dest -> sin_addr = ntohl(((sockaddr_in *) addr) -> sin_addr.s_addr);

  sock -> addr_in_dest = address_in_dest;

  int dest_port;
  in_port_t local_port;
  uint32_t local_ip;
  std::optional<ipv4_t> local_ipv4;
  std::vector <Socket *>::iterator it;
  
  ipv4_t ip_dest;
  std::memcpy(&ip_dest, (void *) &address_in_dest -> sin_addr, 4);
  
  // std::optional<ipv4_t> ip = getHost() -> getIPAddr()

  dest_port = getHost() -> getRoutingTable(ip_dest);
  local_ipv4 = this -> getHost() -> getIPAddr(dest_port);
  std::memcpy(&local_ip, (void *) &local_ipv4, 4);

  Sockad_in *address_in_src = new Sockad_in;
  address_in_src -> sin_family = AF_INET;
  address_in_src -> sin_port = ntohs(local_port);
  address_in_src -> sin_addr = ntohl(local_ip);

  sock -> addr_in = address_in_src;
  sock -> seq_num = rand();
  sock -> ack_num = 0;

  Packet packet = createPacket(sock, SYN);
  std::cout << "connect: Sending SYN packet" << std::endl;
  sendPacket("IPv4", std::move(packet));

  // expect ACK
  listenList.push_back (sock);

  sock -> state = SS_CONNECTED;
  sock -> seq_num++;

  this -> connect_lock_UUID = syscallUUID;

}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, 
                                   int sockfd, int backlog) 
{
  Socket *sock = getSocket(pid, sockfd);

  // std::cout << "backlog : " << backlog;

  if (sock == NULL) {
    this -> returnSystemCall(syscallUUID, -1);
    return;
  }

  if (sock -> state != SS_BIND) {
    this -> returnSystemCall(syscallUUID, -1);
    return;
  }

  if (backlog < listenList.size() || backlog < 0) {
    this -> returnSystemCall(syscallUUID, -1);
    return;
  }

  sock -> state = SS_LISTEN;
  listenList.push_back(sock);
  this -> returnSystemCall(syscallUUID, 0);

}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, 
                                   int socketfd, struct sockaddr *address, socklen_t *address_len) 
{
  Socket *sock = getSocket(pid, socketfd);
  Socket *connection_sock;
  int fd;

  if (sock -> connection_queue.size() == 0) {
    std::cout << "connection queue is empty\n";
    // sockaddr_in *addr_in = (sockaddr_in *) address;
    // memset(addr_in, 0, sizeof(struct sockaddr_in));
    // addr_in -> sin_addr.s_addr = htonl(sock -> addr_in -> sin_addr);
    // addr_in -> sin_port = htons(sock -> addr_in -> sin_port);
    // addr_in -> sin_family = AF_INET;
    // this -> returnSystemCall(syscallUUID, 0);
    return;
  }

  connection_sock = sock -> connection_queue.front();
  sock -> connection_queue.erase(sock -> connection_queue.begin());

  if ((fd = createFileDescriptor(pid)) == -1) {
    this -> returnSystemCall(syscallUUID, -1);
    return;
  }
  connection_sock->fd = fd;

  socketList.push_back(connection_sock);

  sockaddr_in *addr_in = (sockaddr_in *) address;
  addr_in -> sin_addr.s_addr = htonl(connection_sock -> addr_in_dest -> sin_addr);
  addr_in -> sin_port = htons(connection_sock -> addr_in_dest -> sin_port);
  addr_in -> sin_family = AF_INET;
  
  this -> returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd,
    		                         struct sockaddr *addr, socklen_t addrlen)
{
  // The only value you should assign to sin_family is AF_INET.  
  // The two fields, sin_port and sin_addr, must follow the network byte order. 
  // The sin_addr field must be either an IP address or INADDR_ANY. 
  // You should implement both cases.
  Socket *sock = getSocket(pid, sockfd);
  Sockad_in *address_in;
  std::vector <Socket *>::iterator it;

  if (sock == NULL) {
    this -> returnSystemCall(syscallUUID, -1);
    return;
  }

  if (sock -> addr_in != NULL) {
    this -> returnSystemCall(syscallUUID, -1);
    return;
  }

  for (it = socketList.begin(); it != socketList.end(); it++) {
    Socket *socket_temp = (*it);
    if (socket_temp -> addr_in != NULL) {
      if (socket_temp -> addr_in -> sin_port == ntohs(((sockaddr_in *) addr) -> sin_port))
      {
        if (socket_temp -> addr_in -> sin_addr == ntohs(INADDR_ANY)
            || socket_temp -> addr_in -> sin_addr == ntohs(((sockaddr_in *) addr) -> sin_addr.s_addr))
        {
          this -> returnSystemCall(syscallUUID, -1);
          return;
        }
      }
    }
  }

  address_in = new Sockad_in;
  address_in -> sin_family = AF_INET;
  address_in -> sin_port = ntohs(((sockaddr_in *) addr) -> sin_port);
  address_in -> sin_addr = ntohl(((sockaddr_in *) addr) -> sin_addr.s_addr);
  
  sock -> addr_in = address_in;
  sock -> state = SS_BIND;

  this -> returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
    		                                struct sockaddr *address, socklen_t* address_len) 
{
  // It should return the current address to which the socket is bound. 
  // Upon successful completion, 0 shall be returned, 
  // the address argument shall point to the address of the socket, 
  // and the address_len argument shall point to the length of the address.
  Socket *sock = getSocket(pid, sockfd);

  if (sock == NULL) {
    this -> returnSystemCall(syscallUUID, -1);
  }

  if (sock -> addr_in == NULL) {
    this -> returnSystemCall(syscallUUID, -1);
    return;
  }

  ((sockaddr_in *) address) -> sin_family = sock -> addr_in -> sin_family;
  ((sockaddr_in *) address) -> sin_addr.s_addr = htonl(sock -> addr_in -> sin_addr);
  ((sockaddr_in *) address) -> sin_port = htons(sock -> addr_in -> sin_port);
  *address_len = sizeof (struct sockaddr_in);
  this -> returnSystemCall(syscallUUID, 0);

}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int param1,
                                       struct sockaddr *param2, socklen_t *param3)
{
  syscall_getsockname(syscallUUID, pid, param1, param2, param3);
}


} // namespace E
