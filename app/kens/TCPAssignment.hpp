/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <E/E_TimerModule.hpp>

#include <E/E_Common.hpp>

#define MAX_SOCKETS 1 << 16

namespace E {

typedef enum
{
  SS_FREE = 0,
  SS_UNCONNECTED,
  SS_CONNECTING,
  SS_CONNECTED,
  SS_DISCONNECTING
} socket_state;

struct Socket
{
  UUID socketUUID;
  socket_state state;
  int fd;
  int pid;
  int domain;       /* AF_INET */
  short type;         /* SOCK_STREAM */
  int protocol;     /* PROTOCOLS */
  int connected;
  struct sockaddr saddr;
};

class TCPAssignment : public HostModule,
                      public NetworkModule,
                      public SystemCallInterface,
                      private NetworkLog,
                      private TimerModule {
private:
private:
  virtual void timerCallback(std::any payload) final;

public:
  TCPAssignment(Host *host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;

  virtual int syscall_socket (UUID syscallUUID, int pid,
                              int domain, int type, int protocol);
  virtual int syscall_bind (UUID syscallUUID, int pid,
                                           int socket, struct sockaddr *address,
                                           socklen_t address_len);
  virtual int syscall_getsockname (UUID syscallUUID, int pid,
                                   int sockfd, struct sockaddr *address,
                                   socklen_t *address_len);
  virtual int syscall_connect (UUID syscallUUID, int pid,
                               int sockfd, struct sockaddr *address,
                               socklen_t address_len);
  virtual int syscall_close (UUID syscallUUID, int pid,
                             int fildes);
  virtual struct Socket * SockfdLookup (int fd);

  std::array <struct Socket *, MAX_SOCKETS> sockList;
};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static HostModule *allocate(Host *host) { return new TCPAssignment(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */
