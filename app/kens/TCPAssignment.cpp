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
  sockList = std::array<struct Socket *, MAX_SOCKETS> ();
  sockList.fill (nullptr);
}

void TCPAssignment::finalize() {}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {
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

int TCPAssignment::syscall_socket (UUID syscallUUID, int pid,
                                   int domain, int type, int protocol)
{
  int fd;
  if ((fd = createFileDescriptor (pid)) == -1)
  {
    returnSystemCall (syscallUUID, -1);
  }
  struct Socket *newSocket = new struct Socket;
  newSocket->socketUUID = syscallUUID;
  newSocket->fd = fd;
  newSocket->pid = pid;
  newSocket->domain = domain;
  newSocket->type = type;
  newSocket->protocol = protocol;
  sockList[fd] = newSocket;

  returnSystemCall (syscallUUID, fd);
}

int TCPAssignment::syscall_bind (UUID syscallUUID, int pid,
                                 int fd, struct sockaddr *address,
                                 socklen_t address_len)
{
  struct Socket *sock;
  struct sockaddr_in addr;
  int err = -1;

  /* Lookup the socket list. */
  sock = SockfdLookup (fd);
  if (sock)
  {
    memcpy (address, &addr, address_len);
  }

  returnSystemCall (syscallUUID, err);
}

int TCPAssignment::syscall_getsockname (UUID syscallUUID, int pid,
                                        int fd, struct sockaddr *address,
                                        socklen_t *address_len)
{
  struct Socket *sock;
  int err = -1;

  sock = SockfdLookup (fd);
  if (sock)
  {
    *address = sock->saddr;
    *address_len = sizeof (sock->saddr);
    err = 0;
  }

  returnSystemCall (syscallUUID, err);
}

struct Socket * TCPAssignment::SockfdLookup (int fd)
{
  return sockList[fd] == nullptr ? nullptr : sockList[fd];
}

} // namespace E
