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

const uint8_t FIN = 1;
const uint8_t SYN = 2;
const uint8_t RST = 4;
const uint8_t PSH = 8;
const uint8_t ACK = 16;
const uint8_t URG = 32;

typedef enum
{
  SS_FREE = 0,
  SS_BIND,
  SS_LISTEN,
  SS_SYNSENT,
  SS_ACCEPT,
  SS_SYNRCVD,
  SS_CONNECTED,
  SS_DISCONNECTING
} socket_state;

struct Sockad_in
{
  sa_family_t sin_family;
  in_port_t sin_port;
  uint32_t sin_addr;
  char sin_zero[8];
};

struct TCPlayer
{
  void *send_buf;
  std::vector <Packet> send_buf;
  int window_size;
  int send_base;

  void *recv_buf;
  std::vector <Packet> recv_buf;
  int rcv_base;
};

struct Socket
{
  // Everything in HOST ORDER
  UUID syscallUUID;
  socket_state state;
  int fd;
  int pid;
  int domain;       /* AF_INET */
  int type;         /* SOCK_STREAM */
  int protocol;     /* PROTOCOLS */
  int backlog;
  Sockad_in *accept_waiting;
  std::vector <Socket *> complete_queue;
  std::vector <Socket *> incomplete_queue;
  
  uint32_t seq;
  uint32_t ack;

  // Address info used when creating a packet
  struct Sockad_in *addr_in_src;
  struct Sockad_in *addr_in_dst;

  // ONLY for accept
  Socket * sock_con;
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

  Socket * getSocket (int pid, int fd);
  Packet createPacket (Socket *sock, const uint8_t flag);

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;

  virtual void syscall_socket (UUID syscallUUID, int pid,
                              int domain, int type, int protocol);
  virtual void syscall_bind (UUID syscallUUID, int pid,
                                           int socket, struct sockaddr *address,
                                           socklen_t address_len);
  virtual void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
  virtual void syscall_accept(UUID syscallUUID, int pid, int sockfd,
    		              struct sockaddr *address,
    		              socklen_t *address_len);
  virtual void syscall_getsockname (UUID syscallUUID, int pid,
                                   int sockfd, struct sockaddr *address,
                                   socklen_t *address_len);
  virtual void syscall_connect (UUID syscallUUID, int pid,
                               int sockfd, struct sockaddr *address,
                               socklen_t address_len);
  virtual void syscall_close (UUID syscallUUID, int pid,
                             int fildes);
  virtual void syscall_read (UUID syscallUUID, int pid,
                            int sockfd, void *buf, size_t count);
  virtual void syscall_write (UUID syscallUUID, int pid,
                            int sockfd, const void *buf, size_t count);
  virtual void syscall_getpeername (UUID syscallUUID, int pid,
            int fd, struct sockaddr *address,
            socklen_t *address_len);
  bool isMatchingAddr (Socket *sock, uint32_t ip, uint16_t port);
  bool isMatchingAddrDst (Socket *sock, uint32_t ip, uint16_t port);

  std::vector <Socket *> socketList;
  std::vector <Socket *> listenList;
  std::vector <Socket *> acceptList;
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
