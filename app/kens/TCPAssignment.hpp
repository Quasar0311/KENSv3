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



namespace E {

const uint8_t FIN = 1;
const uint8_t SYN = 2;
const uint8_t RST = 4;
const uint8_t PSH = 8;
const uint8_t ACK = 16;
const uint8_t URG = 32;

struct Sockad_in {
  sa_family_t    sin_family; /* address family: AF_INET */
  in_port_t      sin_port;   /* port in network byte order */
  uint32_t sin_addr;   /* internet address */
};

typedef enum
{
  SS_FREE = 0,
  SS_UNCONNECTED,
  SS_BIND,
  SS_LISTEN,
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
  int type;         /* SOCK_STREAM */
  int protocol;     /* PROTOCOLS */
  int connected;

  uint32_t seq_num;
  uint32_t ack_num;

  struct Sockad_in *addr_in;
  struct Sockad_in *addr_in_dest;

  std::vector <Socket *> connection_queue;
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

  UUID connect_lock_UUID;

  Socket *getSocket(int pid, int fd);
  void eraseInsocketList(Socket *sock);
  Packet createPacket(Socket *sock, const uint8_t flag);

  void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
  void syscall_close(UUID syscallUUID, int pid, int fd);
  void syscall_read(UUID syscallUUID, int pid, int param1, void *param2, int param3);
  void syscall_write(UUID syscallUUID, int pid, int param1, void *param2, int param3);
  void syscall_connect(UUID syscallUUID, int pid, int sockfd, 
                       struct sockaddr *addr, 
                       socklen_t addrlen);
  void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
  void syscall_accept(UUID syscallUUID, int pid, int sockfd,
    		              struct sockaddr *address,
    		              socklen_t *address_len);
  void syscall_bind(UUID syscallUUID, int pid, int sockfd,
    		            struct sockaddr *addr,
    		            socklen_t addrlen);
  void syscall_getsockname(UUID syscallUUID, int pid, int sockfd,
    		                   struct sockaddr *address,
    		                   socklen_t* address_len);
  void syscall_getpeername(UUID syscallUUID, int pid, int param1,
                           struct sockaddr *param2,
                           socklen_t *param3);

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;

  // virtual void syscall_socket (UUID syscallUUID, int pid,
  //                              int domain, int type, int protocol);
  std::vector <Socket *> socketList;
  std::vector <Socket *> listenList;
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
