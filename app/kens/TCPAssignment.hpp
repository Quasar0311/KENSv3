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

namespace E {

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

  int syscall_socket(UUID syscallUUID, int pid, int param1, int param2, int param3);
  int syscall_close(UUID syscallUUID, int pid, int param1);
  void syscall_read(UUID syscallUUID, int pid, int param1, void *param2, int param3);
  void syscall_write(UUID syscallUUID, int pid, int param1, void *param2, int param3);
  void syscall_connect(UUID syscallUUID, int pid, int param1, 
                       struct sockaddr *param2, 
                       socklen_t param3);
  void syscall_listen(UUID syscallUUID, int pid, int param1, int param2);
  void syscall_accept(UUID syscallUUID, int pid, int param1,
    		              struct sockaddr *param2,
    		              socklen_t *param3);
  void syscall_bind(UUID syscallUUID, int pid, int param1,
    		            struct sockaddr *param2,
    		            socklen_t param3);
  void syscall_getsockname(UUID syscallUUID, int pid, int param1,
    		                   struct sockaddr *param2,
    		                   socklen_t* param3);
  void syscall_getpeername(UUID syscallUUID, int pid, int param1,
                           struct sockaddr *param2,
                           socklen_t *param3);

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
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
