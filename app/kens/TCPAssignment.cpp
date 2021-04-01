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
  connect_lock_UUID = 0;
}

void TCPAssignment::finalize() {}

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
  
  // ip
  pkt.writeData(14 + 12, &addr_from_ip, 4);
  pkt.writeData(14 + 16, &addr_to_ip, 4);
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

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
  
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

  packet.readData(14 + 12, &addr_from_ip, 4);
  packet.readData(14 + 16, &addr_to_ip, 4);
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

  socketList.push_back(newSocket);

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
  Sockad_in *address_in = new Sockad_in;
  
  if (sock == NULL) {
    this -> returnSystemCall(syscallUUID, -1);
    return;
  }
  
  address_in -> sin_family = AF_INET;
  address_in -> sin_port = ntohs(((sockaddr_in *) addr) -> sin_port);
  address_in -> sin_addr = ntohl(((sockaddr_in *) addr) -> sin_addr.s_addr);

  sock -> addr_in_dest = address_in;

  int dest_port;
  in_port_t local_port;
  uint32_t local_ip;
  std::optional<ipv4_t> local_ipv4;
  std::vector <Socket *>::iterator it;
  
  ipv4_t ip_dest;
  std::memcpy(&ip_dest, (void *) &address_in -> sin_addr, 4);
  
  // std::optional<ipv4_t> ip = getHost() -> getIPAddr()

  dest_port = getHost() -> getRoutingTable(ip_dest);
  local_ipv4 = this -> getHost() -> getIPAddr(dest_port);
  std::memcpy(&local_ip, (void *) &local_ipv4, 4);

  while (true) {
    int iter = 0;
    local_port = rand() % 65536;
    for (it = socketList.begin(); it != socketList.end(); it++) {
      Socket *socket_temp = (*it);
      if (socket_temp -> addr_in -> sin_port == local_port) {
        if (socket_temp -> addr_in -> sin_addr == ntohs(INADDR_ANY)
            || socket_temp -> addr_in -> sin_addr == local_ip) 
        {
          iter = 1;
          break;
        }
      }
    }
    if (iter == 0) {
      break;
    }
  }

  Sockad_in *address_in_dest = new Sockad_in;
  address_in_dest -> sin_family = AF_INET;
  address_in_dest -> sin_port = ntohs(local_port);
  address_in_dest -> sin_addr = ntohl(local_ip);

  sock -> addr_in = address_in_dest;
  sock -> seq_num = rand();
  sock -> ack_num = 0;

  Packet packet = createPacket(sock, SYN);
  sendPacket("IPv4", std::move(packet));
  
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
                                   int param1, struct sockaddr *param2, socklen_t *param3) 
{

}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd,
    		                         struct sockaddr *addr, socklen_t addrlen)
{
  // The only value you should assign to sin_family is AF_INET.  
  // The two fields, sin_port and sin_addr, must follow the network byte order. 
  // The sin_addr field must be either an IP address or INADDR_ANY. 
  // You should implement both cases.
  Socket *sock = getSocket(pid, sockfd);
  Sockad_in *address_in = new Sockad_in;
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
  // *address_len = 
  this -> returnSystemCall(syscallUUID, 0);

}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int param1,
                                       struct sockaddr *param2, socklen_t *param3)
{
  
}


} // namespace E
