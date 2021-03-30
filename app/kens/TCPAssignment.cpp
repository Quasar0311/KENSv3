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
                                    int param1, struct sockaddr *param2, socklen_t param3) 
{

}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, 
                                   int param1, int param2) 
{

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

  if (sock == NULL) {
    this -> returnSystemCall(syscallUUID, -1);
  }

  if (sock -> addr_in != NULL) {
    this -> returnSystemCall(syscallUUID, -1);
    return;
  }

  address_in -> sin_family = AF_INET;
  address_in -> sin_port = ntohs(((sockaddr_in *) &addr) -> sin_port);
  address_in -> sin_addr = ntohl(((sockaddr_in *) &addr) -> sin_addr.s_addr);
  
  sock -> addr_in = address_in;

  this -> returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int param1,
    		                                struct sockaddr *param2, socklen_t* param3) 
{

}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int param1,
                                       struct sockaddr *param2, socklen_t *param3)
{
  
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  (void)fromModule;
  (void)packet;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
}



} // namespace E
