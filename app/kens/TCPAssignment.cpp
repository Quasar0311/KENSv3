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
  acceptList = std::vector <std::pair<UUID, Socket *>>();
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

  in_addr_t addr_from_ip = (in_addr_t) htonl(addr_from -> sin_addr);
  in_addr_t addr_to_ip = (in_addr_t) htonl(addr_to -> sin_addr);
  in_port_t addr_from_port = (in_port_t) htons(addr_from -> sin_port);
  in_port_t addr_to_port = (in_port_t) htons(addr_to -> sin_port);
  
  Packet pkt(54);
  
  // ip
  pkt.writeData(14 + 12, &addr_from_ip, 4);
  pkt.writeData(14 + 16, &addr_to_ip, 4);
  pkt.writeData(34, &addr_from_port, 2);
  pkt.writeData(34 + 2, &addr_to_port, 2);

  uint32_t seq = htonl (sock -> seq_num);
  uint32_t ack = htonl (sock -> ack_num);


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

void TCPAssignment::printPacket (Packet &&packet)
{
  uint32_t addr_from_ip;
  uint32_t addr_to_ip;
  uint16_t addr_from_port;
  uint16_t addr_to_port;
  uint16_t checksum;
  
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
  packet.readData(34 + 16, &checksum, 2);

  addr_from_ip = ntohl(addr_from_ip);
  addr_from_port = ntohs(addr_from_port);
  addr_to_ip = ntohl(addr_to_ip);
  addr_to_port = ntohs(addr_to_port);

  seq = ntohl(seq);
  ack = ntohl(ack);

  std::cout << "source ip: " << addr_from_ip
            << " source port: " << addr_from_port
            << " dest ip: " << addr_to_ip
            << " dest port: " << addr_to_port
            << " flag: " << flag
            << " seq: " << seq << " ack: " << ack
            << " head_len: " << head_len << " checksum: " << checksum 
            << std::endl;
}

Sockad_in *TCPAssignment::assignAddress(Sockad_in *sockad_in, uint32_t ip, in_port_t port) {
  sockad_in -> sin_addr = ip;
  sockad_in -> sin_port = port;
  sockad_in -> sin_family = AF_INET;

  return sockad_in;
}

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  printPacket (std::move(packet));
  getchar();
  uint32_t addr_from_ip;
  uint32_t addr_to_ip;
  uint16_t addr_from_port;
  uint16_t addr_to_port;
  uint16_t checksum;

  uint32_t seq;
  uint32_t ack;
  uint8_t head_len;
  uint8_t flag;
  // uint16_t window;
  packet.readData(14 + 12, &addr_from_ip, 4);
  packet.readData(14 + 16, &addr_to_ip, 4);

  packet.readData(34 + 16, &checksum, 2);
  uint8_t tcp_seg_buf[20];
  uint16_t checksum_cal = NetworkUtil::tcp_sum(addr_from_ip, addr_to_ip, tcp_seg_buf, 20);
  // if (checksum != ~checksum_cal)
  // {
  //   std::cout << "wrong checksum" << std::endl;
  //   return;
  // }
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
    if ((sock -> addr_in -> sin_addr == addr_to_ip || sock -> addr_in -> sin_addr == htonl(INADDR_ANY)) && sock -> addr_in ->sin_port == addr_to_port) {
      // Client or Server
      if (sock->state == SS_LISTEN)
      {
        if (flag & SYN)
        {
          // acceptList에 <?, sock>가 있으면, accept가 block 중이라는 것
          std::vector <std::pair<UUID, Socket *>>::iterator accept_it;
          for (accept_it = acceptList.begin(); accept_it != acceptList.end(); accept_it++)
          {
            std::pair<UUID, Socket *> pair = (*accept_it);
            if ((pair.second->addr_in->sin_addr == addr_to_ip || pair.second->addr_in->sin_addr == htonl (INADDR_ANY))
              && pair.second->addr_in->sin_port == addr_to_port)
            {
              Packet pkt = createPacket (pair.second, SYN | ACK);
              sendPacket ("IPv4", std::move(pkt));
              pair.second->state = SS_SYNRCVD;
              return;
            }
          }
          // 없으면, connection_queue에 넣어주면 됨
          if (sock->connection_queue.size() >= sock->backlog)
          {
            std::cout << "backlog: " << sock->backlog << std::endl;
            return;
          }
          sock->addr_in_dest->sin_addr = addr_from_ip;
          sock->addr_in_dest->sin_port = addr_from_port;
          sock->addr_in_dest->sin_family = AF_INET;
          sock->seq_num = ack;
          sock->ack_num = seq + 1;
          sock->state = SS_SYNRCVD;

          Socket *connection_candidate_socket = new Socket;
          connection_candidate_socket->addr_in->sin_addr = addr_from_ip;
          connection_candidate_socket->addr_in->sin_port = addr_from_port;
          connection_candidate_socket->addr_in->sin_family = AF_INET;
          connection_candidate_socket->seq_num = ack;
          connection_candidate_socket->ack_num = seq + 1;
          sock->connection_queue.push_back (connection_candidate_socket);

          Packet pkt = createPacket (sock, SYN | ACK);
          sendPacket ("IPv4", std::move(pkt));
        }
        return;
      }
      // Client
      if (sock->state == SS_SYNSENT)
      {
        if (flag & (SYN | ACK))
        {
          sock->seq_num = ack;
          sock->ack_num = seq + 1;
          Packet pkt = createPacket (sock, ACK);
          sendPacket ("IPv4", std::move(pkt));
          listenList.erase (it);
          sock->state = SS_CONNECTED;
          this -> returnSystemCall(sock -> socketUUID, 0);
        }
        return;
      }
      // Server
      if (sock->state == SS_SYNRCVD)
      {
        if (flag & ACK)
        {
          std::vector <std::pair<UUID, Socket *>>::iterator accept_it;
          for (accept_it = acceptList.begin(); accept_it != acceptList.end(); accept_it++)
          {
            std::pair<UUID, Socket *> pair = (*accept_it);
            if ((pair.second->addr_in->sin_addr == addr_to_ip || pair.second->addr_in->sin_addr == htonl (INADDR_ANY))
              && pair.second->addr_in->sin_port == addr_to_port)
            {
              int fd;
              acceptList.erase (accept_it);

              if ((fd = createFileDescriptor(sock->pid)) == -1) {
                listenList.erase (it);
                this -> returnSystemCall(pair.first, -1);
                return;
              }

              Socket *newSocket = new Socket;
              newSocket->socketUUID = pair.first;
              newSocket->fd = fd;
              newSocket->pid = sock->pid;
              // newSocket->domain = domain;
              // newSocket->type = type;
              // newSocket->protocol = protocol;
              newSocket->addr_in = new Sockad_in;
              newSocket->addr_in_dest = new Sockad_in;
              newSocket->state = SS_CONNECTED;
              newSocket->ack_num = 0;
              newSocket->seq_num = 0;
              newSocket->connection_queue = std::vector <Socket *>();

              newSocket -> addr_in_dest -> sin_addr = addr_from_ip;
              newSocket -> addr_in_dest -> sin_port = addr_from_port;
              newSocket -> addr_in_dest -> sin_family = AF_INET;

              // TODO: newSocket->addr_in 에 Host() 정보
              newSocket -> addr_in -> sin_addr = addr_to_ip;
              newSocket -> addr_in -> sin_port = addr_to_port;
              newSocket -> addr_in -> sin_family = AF_INET;

              socketList.push_back(newSocket);

              std::cout << "before accept ends\n";
              
              std::cout << "server side socket addr1 : " << sock -> addr_in -> sin_addr
                        << " server side socket addr2 : " << sock -> addr_in_dest -> sin_addr
                        << " server side port 1 : " << sock -> addr_in -> sin_port
                        << " server side port 2 : " << sock -> addr_in_dest -> sin_port << std::endl;
              
              listenList.erase (it);
              pair.second->state = SS_CONNECTED;
              this -> returnSystemCall(pair.first, fd);
            }
          }

          if (accept_it == acceptList.end())
          {
            Socket *connection_candidate_socket = sock->connection_queue.front();
            connection_candidate_socket->addr_in_dest = connection_candidate_socket->addr_in;
            assignAddress (connection_candidate_socket->addr_in, addr_to_ip, addr_to_port);
            connection_candidate_socket->seq_num = ack;
            connection_candidate_socket->ack_num = seq + 1;

            returnSystemCall (connection_candidate_socket->socketUUID, connection_candidate_socket->pid);
          }
        }
        return;
      }
    }
  }

// --------------

  // std::vector <Socket *>::iterator it;
  // for (it = socketList.begin(); it != socketList.end(); it++) {
  //   Socket *sock = *it;
  //   if ((sock -> addr_in -> sin_addr == addr_to_ip || sock -> addr_in -> sin_addr == htonl(INADDR_ANY)) && sock -> addr_in ->sin_port == addr_to_port) {
  //     if (sock -> addr_in_dest -> sin_addr == 0) {
  //       // std :: cout << "state : " << sock -> state << "\n";
  //       sock_found = sock;
  //       break;
  //     }
  //     if ((sock -> addr_in_dest -> sin_addr == addr_from_ip || sock -> addr_in_dest -> sin_addr == htonl(INADDR_ANY)) && sock -> addr_in_dest -> sin_port == addr_from_port) {
  //       sock_found = sock;
  //       std :: cout << "got it!\n";
  //       break;
  //     }
  //     else {
  //       continue;
  //     }
  //   }
  //   else {
  //     continue;
  //   }
  // }

  // if (sock_found == NULL) {
  //   std::cout << "Not found\n";
  // }
  // std::cout << "seq_num : " << sock_found -> seq_num << ", flag : " << flag <<"\n";
  // switch (sock_found -> state) {
  //   case SS_LISTEN: {
  //     std :: cout << "sock ip : " << sock_found -> addr_in -> sin_addr << "\n";

  //     sock_found -> addr_in -> sin_addr = addr_from_ip;
  //     sock_found -> addr_in -> sin_port = addr_from_port;
  //     sock_found -> addr_in -> sin_family = AF_INET;

  //     sock_found -> addr_in_dest -> sin_addr = addr_to_ip;
  //     sock_found -> addr_in_dest -> sin_port = addr_to_port;
  //     sock_found -> addr_in_dest -> sin_family = AF_INET;
  //     sock_found -> seq_num = rand();
  //     sock_found -> ack_num = seq + 1;
  //     Packet pkt = createPacket(sock_found, SYN + ACK);
  //     printPacket (std::move(pkt));

  //     this -> sendPacket("IPv4", std::move(pkt));
  //     break;
  //   }
  //   default: {
  //     break;
  //   }
  // }
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

  std::cout << "syscalluuid: " << syscallUUID
            << " number: " << param.syscallNumber << std::endl;
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
  newSocket->addr_in = new Sockad_in;
  newSocket->addr_in_dest = new Sockad_in;
  newSocket->state = SS_FREE;
  newSocket->ack_num = 0;
  newSocket->seq_num = 0;
  newSocket->backlog = 0;
  newSocket->connection_queue = std::vector <Socket *>();

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
  std::cout << "connecting...\n";
  if (sock == NULL) {
    this -> returnSystemCall(syscallUUID, -1);
    return;
  }

  // server 
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
  // std::memcpy(&ip_dest, (void *) &address_in -> sin_addr, 4);
  ip_dest = NetworkUtil::UINT64ToArray<4>(address_in -> sin_addr);
  
  // std::optional<ipv4_t> ip = getHost() -> getIPAddr()

  dest_port = getHost() -> getRoutingTable(ip_dest);
  local_ipv4 = this -> getHost() -> getIPAddr(dest_port);
  
  // std::memcpy(&local_ip, (void *) &local_ipv4, 4);
  local_ip = NetworkUtil::arrayToUINT64<4>(local_ipv4.value());

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

  Sockad_in *address_in_src = new Sockad_in;
  address_in_src -> sin_family = AF_INET;
  address_in_src -> sin_port = ntohs(local_port);
  address_in_src -> sin_addr = ntohl(local_ip);

  sock -> addr_in = address_in_src;
  sock -> seq_num = rand();
  sock -> ack_num = 0;

  Packet packet = createPacket(sock, SYN);
  listenList.push_back (sock);
  
  sock -> state = SS_SYNSENT;
  sock -> socketUUID = syscallUUID;

  this -> connect_lock_UUID = syscallUUID;
  this -> sendPacket("IPv4", std::move(packet));
  return;
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, 
                                   int sockfd, int backlog) 
{
  Socket *sock = getSocket(pid, sockfd);

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

  std:: cout << "sock state : " << sock -> state << "\n";
  sock -> state = SS_LISTEN;
  sock->backlog = backlog;
  listenList.push_back(sock);
  // std::cout << "listen from : " << sock -> addr_in -> sin_addr << ", to : " << sock -> addr_in_dest ->sin_addr << "\n";
  this -> returnSystemCall(syscallUUID, 0);

}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, 
                                   int socketfd, struct sockaddr *address, socklen_t *address_len) 
{
  Socket *sock = getSocket(pid, socketfd);
  Socket *connection_candidate_socket;
  Sockad_in *addr_in_client;
  Socket *newSocket = new Socket;
  int fd;

  if (sock -> connection_queue.size() == 0) {
    std::cout << "connection queue is empty\n";
    // acceptList에 <syscalluuid, sock> push
    acceptList.push_back (std::pair(syscallUUID, sock));
    return;
  }

  else {
    // 새로 server가 알고있는 client socket 만들기Socket *newSocket = new Socket; (SYNSENT, LISTEN)
    connection_candidate_socket = sock->connection_queue.front();
    addr_in_client = connection_candidate_socket->addr_in;
    // sock -> connection_queue.erase(sock -> connection_queue.begin());
    
    if ((fd = createFileDescriptor(pid)) == -1) {
      this -> returnSystemCall(syscallUUID, -1);
      return;
    }
    connection_candidate_socket->fd = fd;
    connection_candidate_socket->socketUUID = syscallUUID;

    sock->addr_in_dest = addr_in_client;
    sock->seq_num = connection_candidate_socket->seq_num;
    sock->ack_num = connection_candidate_socket->ack_num;
    Packet pkt = createPacket (sock, (SYN | ACK));
    sock->state = SS_SYNRCVD;
    return;
    
    // newSocket->fd = fd;
    // newSocket->socketUUID = syscallUUID;
    // newSocket->pid = pid;
    // // newSocket->domain = domain;
    // // newSocket->type = type;
    // // newSocket->protocol = protocol;
    // newSocket->addr_in = new Sockad_in;
    // newSocket->addr_in_dest = new Sockad_in;
    // newSocket->connection_queue = std::vector <Socket *>();

    // // newSocket->addr_in = (Sockad_in *) addr_in_client;
    // // TODO: newSocket->addr_in 에 Host() 정보
    // // newSocket->addr_in = (Sockad_in*) addr_in_client;
    // // 맨 처음 client 측에서 만든 addr 정보가 다시 서버로 넘어왔고, 서버 측에서 새로 만든 소켓에서
    // // addr_in은 서버 측의 정보, addr_in_dest는 맨 처음 client 측의 addr 정보가 될 것이다.
    // newSocket -> addr_in -> sin_addr = sock -> addr_in -> sin_addr;
    // newSocket -> addr_in -> sin_port = sock -> addr_in -> sin_port;
    // newSocket -> addr_in -> sin_family = AF_INET;

    // newSocket -> addr_in_dest -> sin_addr = addr_in_client -> sin_addr;
    // newSocket -> addr_in_dest -> sin_port = addr_in_client -> sin_port;
    // newSocket -> addr_in_dest -> sin_family = AF_INET;
    // // newSocket -> addr_in -> sin_family = AF_INET;
    // std::cout << "sin_family: " << newSocket->addr_in->sin_family
    //           << " sin_port: " << newSocket->addr_in->sin_port
    //           << " sin_addr: " << newSocket->addr_in->sin_addr 
    //           << " ser sin_fam: " << sock -> addr_in -> sin_family
    //           << " ser port: " << sock -> addr_in -> sin_port
    //           << " ser addr: " << sock -> addr_in -> sin_addr << std::endl;
    // socketList.push_back(newSocket);

    // sock->state = SS_CONNECTED;
    // newSocket->state = SS_CONNECTED;
    // sockaddr_in *addr_in = (sockaddr_in *) address;
    // addr_in -> sin_addr.s_addr = newSocket -> addr_in_dest -> sin_addr;
    // addr_in -> sin_port = newSocket -> addr_in_dest -> sin_port;
    // addr_in -> sin_family = AF_INET;
    
    // this -> returnSystemCall(syscallUUID, fd);
  }
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
    std :: cout << "e1\n";
    this -> returnSystemCall(syscallUUID, -1);
    return;
  }

  // if (sock -> addr_in -> sin_addr == 0) {
  //   std :: cout << "e2\n";
  //   this -> returnSystemCall(syscallUUID, -1);
  //   return;
  // }

  for (it = socketList.begin(); it != socketList.end(); it++) {
    Socket *socket_temp = (*it);
    if (socket_temp -> addr_in != NULL) {
      if (socket_temp -> addr_in -> sin_port == ntohs(((sockaddr_in *) addr) -> sin_port))
      {
        if (socket_temp -> addr_in -> sin_addr == ntohs(INADDR_ANY)
            || socket_temp -> addr_in -> sin_addr == ntohs(((sockaddr_in *) addr) -> sin_addr.s_addr))
        {
          std :: cout << "e3\n";
          this -> returnSystemCall(syscallUUID, -1);
          return;
        }
      }
    }
  }

  address_in -> sin_family = AF_INET;
  address_in -> sin_port = ntohs(((sockaddr_in *) addr) -> sin_port);
  address_in -> sin_addr = ntohl(((sockaddr_in *) addr) -> sin_addr.s_addr);

  std::cout << "sin_family: " << address_in->sin_family
            << " sin_port: " << address_in->sin_port
            << " sin_addr: " << address_in->sin_addr << std::endl;
  
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
    std::cout << "no such socket\n";
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
  syscall_getsockname(syscallUUID, pid, param1, param2, param3);
}


} // namespace E
