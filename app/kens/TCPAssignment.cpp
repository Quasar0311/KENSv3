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
#include <E/E_TimeUtil.hpp>
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
}

void TCPAssignment::finalize() {}

Socket * TCPAssignment::getSocket (int pid, int fd)
{
  std::vector <Socket *>::iterator i;
  for (i = socketList.begin(); i != socketList.end(); i++)
  {
    Socket *s = (*i);
    if (s->pid == pid && s->fd == fd)
    {
      return s;
    } 
  }
  return nullptr;
}

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

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  uint16_t ip_length;
  uint16_t ip_id;
  uint32_t ip_src;
  uint32_t ip_dst;
  uint16_t port_src;
  uint16_t port_dst;
  uint16_t checksum;

  uint32_t seq;
  uint32_t ack;
  uint8_t head_len;
  uint8_t flag;
  
  uint16_t window;
  void *payload = nullptr;

  packet.readData(14 + 2, &ip_length, 2);
  packet.readData(14 + 4, &ip_id, 2);
  packet.readData(14 + 12, &ip_src, 4);
  packet.readData(14 + 16, &ip_dst, 4);

  packet.readData(34 + 16, &checksum, 2);
  checksum = ntohs (checksum);
  uint8_t tcp_seg[1500];
  packet.readData (14 + 20, tcp_seg, ntohs(ip_length) - 20);
  uint16_t checksum_cal = NetworkUtil::tcp_sum(ip_src, ip_dst, tcp_seg, ntohs(ip_length) - 20);
  checksum_cal = ~checksum_cal;
  if (checksum_cal != 0)
  {
    return;
  }

  packet.readData(34, &port_src, 2);
  packet.readData(34 + 2, &port_dst, 2);

  packet.readData(34 + 4, &seq, 4);
  packet.readData(34 + 8, &ack, 4);
  packet.readData(34 + 12, &head_len, 1);
  packet.readData(34 + 13, &flag, 1);
  packet.readData(34 + 14, &window, 2);

  ip_id = ntohs (ip_id);
  ip_length = ntohs (ip_length);
  ip_src = ntohl(ip_src);
  port_src = ntohs(port_src);
  ip_dst = ntohl(ip_dst);
  port_dst = ntohs(port_dst);
  window = ntohs(window);

  seq = ntohl(seq);
  ack = ntohl(ack);
  
  // If data packet
  if (ip_length > 40)
  {
    payload = malloc (ip_length - 40);
    packet.readData (54, payload, ip_length - 40);
  }

  Socket *sock = nullptr;
  std::vector <Socket *>::iterator it;
  for (it = listenList.begin(); it != listenList.end(); it++)
  {
    sock = *it;
    if (isMatchingAddr (sock, ip_dst, port_dst))
    {
      if (payload != nullptr)
        goto DATA;
      if (sock->state == SS_LISTEN)
      {
        if (flag == SYN)
        {
          if ((int)(sock -> incomplete_queue.size()) >= sock->backlog)
          {
            return;
          }
          Socket *sock_con = new Socket;
          sock_con->addr_in_dst = new Sockad_in;
          sock_con->addr_in_src = new Sockad_in;
          sock_con->addr_in_dst->sin_family = AF_INET;
          sock_con->addr_in_dst->sin_port = port_src;
          sock_con->addr_in_dst->sin_addr = ip_src;
          sock_con->addr_in_src->sin_family = AF_INET;
          sock_con->addr_in_src->sin_port = port_dst;
          sock_con->addr_in_src->sin_addr = ip_dst;
          sock_con->receive_window = malloc (51200);
          sock_con->window_size = 10;
          sock_con->sn = sock_con->sn_base = sock_con->sn_nextseqnum = 0;
          sock_con->packet_queue = std::vector <Packet> ();
          sock_con->seq = rand();
          sock_con->ack = seq + 1;
          sock->incomplete_queue.push_back (sock_con);
          sock_con -> state = SS_SYNRCVD;
          sock_con->read_waiting = nullptr;
          sock_con->rw_size = 0;
          Packet pkt = createPacket(sock_con, SYN | ACK);
          sendPacket("IPv4", std::move(pkt));
          return;
        }

        if (flag == ACK) {
          std::vector <Socket *>::iterator it;
          Socket *socket = nullptr;
          for (it = sock -> incomplete_queue.begin(); it != sock -> incomplete_queue.end(); it++) {
            socket = *it;
            if(isMatchingAddr(socket, ip_dst, port_dst)) {
              sock -> incomplete_queue.erase(it);
              break;
            }
          }
          if (socket == nullptr)
          {
            return;
          }
          sock -> complete_queue.push_back(socket);

          if (sock -> accept_waiting != nullptr) {
            Socket *sock_con = sock->complete_queue.front();
            sock->complete_queue.erase (sock->complete_queue.begin());
            Sockad_in *_addr = sock -> accept_waiting;

            sock->sock_con = sock_con;
            _addr->sin_family = AF_INET;
            _addr->sin_port = sock_con->addr_in_dst->sin_port;
            _addr->sin_addr = sock_con->addr_in_dst->sin_addr;
            sock_con->pid = sock->pid;
            sock->accept_waiting = nullptr;

            int fd;
            if ((fd = createFileDescriptor (sock_con -> pid)) == -1)
            {
              delete sock_con->addr_in_src;
              delete sock_con->addr_in_dst;
              delete sock_con;
              returnSystemCall (sock->syscallUUID, -1);
              return;
            }
            sock_con->fd = fd;
            // socketList.push_back (sock_con);
            socketList.insert (socketList.begin(), sock_con);
            sock->state = SS_LISTEN;
            sock_con->state= SS_CONNECTED;
            sock_con->expectedseqnum = seq;
            sock_con->seq = ack;
            // listenList.push_back (sock_con);
            listenList.insert (listenList.begin(), sock_con);
            returnSystemCall(sock -> syscallUUID, fd);
            return;
          }
          return;
        }
        if (flag == (FIN | ACK))
        {
          Socket *sock_fin;
          std::vector <Socket *>::iterator it;
          for (it = sock->complete_queue.begin(); it != sock->complete_queue.end(); it++)
          {
            sock_fin = *it;
            if (isMatchingAddrDst (sock_fin, ip_src, port_src))
            {
              break;
            }
          }
          if (it == sock->complete_queue.end())
          {
            for (it = socketList.begin(); it != socketList.end(); it++)
            {
              sock_fin = *it;
              if (isMatchingAddrDst (sock_fin, ip_src, port_src))
              {
                break;
              }
            }
          }
          sock_fin->seq = ack + 1;
          Packet pkt = createPacket (sock_fin, FIN | ACK);
          sendPacket ("IPv4", std::move (pkt));
          return;
        }
        return;
      }
      // if (sock->state == SS_ACCEPT)
      // {
      //   if (flag & SYN)
      //   {
      //     Socket *sock_con = new Socket;
      //     sock_con->addr_in_dst = new Sockad_in;
      //     sock_con->addr_in_src = new Sockad_in;
      //     sock_con->addr_in_dst->sin_family = AF_INET;
      //     sock_con->addr_in_dst->sin_port = port_src;
      //     sock_con->addr_in_dst->sin_addr = ip_src;
      //     sock_con->addr_in_src->sin_family = AF_INET;
      //     sock_con->addr_in_src->sin_port = port_dst;
      //     sock_con->addr_in_src->sin_addr = ip_dst;
      //     sock_con->seq = ack;
      //     sock_con->ack = seq + 1;
      //     sock_con->pid = sock->pid;
      //     sock->sock_con = sock_con;

      //     Packet pkt = createPacket (sock_con, SYN | ACK);
      //     sendPacket ("IPv4", std::move (pkt));
      //     sock->state = SS_SYNRCVD;
      //     return;
      //   }
      // }
      if (sock->state == SS_SYNSENT)
      {
        if (flag == (SYN | ACK))
        {
          cancelTimer (sock->timer);
          sock->seq = ack;
          sock->ack = seq + 1;
          Packet pkt = createPacket(sock, ACK);
          // listenList.erase(std::find (listenList.begin(), listenList.end(), sock));
          sock->state = SS_CONNECTED;          
          sock->addr_in_dst->sin_family = AF_INET;
          sock->addr_in_dst->sin_port = port_src;
          sock->addr_in_dst->sin_addr = ip_src;
          sock->expectedseqnum = sock->ack;
          sendPacket ("IPv4", std::move (pkt));
          returnSystemCall (sock->syscallUUID, 0);
          return;
        }
        if (flag == SYN)
        {
          Socket *sock_con = new Socket;
          sock_con->addr_in_dst = new Sockad_in;
          sock_con->addr_in_src = new Sockad_in;
          sock_con->addr_in_dst->sin_family = AF_INET;
          sock_con->addr_in_dst->sin_port = port_src;
          sock_con->addr_in_dst->sin_addr = ip_src;
          sock_con->addr_in_src->sin_family = AF_INET;
          sock_con->addr_in_src->sin_port = port_dst;
          sock_con->addr_in_src->sin_addr = ip_dst;
          sock_con->seq = rand();
          sock_con->ack = seq + 1;
          Packet pkt = createPacket(sock_con, SYN | ACK);
          sock_con -> state = SS_SYNRCVD;
          sendPacket("IPv4", std::move(pkt));
          return;
        }
        return;
      }
      if (sock->state == SS_SYNRCVD)
      {
        // if (flag & SYN)
        // {
        //   if ((sock->complete_queue.size() + sock -> incomplete_queue.size()) >= sock->backlog)
        //   {
        //     return;
        //   }
        //   Socket *sock_con = new Socket;
        //   sock_con->addr_in_dst = new Sockad_in;
        //   sock_con->addr_in_src = new Sockad_in;
        //   sock_con->addr_in_dst->sin_family = AF_INET;
        //   sock_con->addr_in_dst->sin_port = port_src;
        //   sock_con->addr_in_dst->sin_addr = ip_src;
        //   sock_con->addr_in_src->sin_family = AF_INET;
        //   sock_con->addr_in_src->sin_port = port_dst;
        //   sock_con->addr_in_src->sin_addr = ip_dst;
        //   sock_con->seq = ack;
        //   sock_con->ack = seq + 1;
        //   sock->incomplete_queue.push_back (sock_con);
        //   Packet pkt = createPacket(sock_con, SYN | ACK);
        //   sock_con -> state = SS_SYNRCVD;
        //   sendPacket("IPv4", std::move(pkt));
        //   return;
        // }
        if (flag == ACK)
        {
          Socket *sock_con = sock->sock_con;
          int fd;
          if ((fd = createFileDescriptor (sock_con->pid)) == -1)
          {
            delete sock_con->addr_in_src;
            delete sock_con->addr_in_dst;
            delete sock_con;
            returnSystemCall (sock->syscallUUID, -1);
            return;
          }
          sock_con->fd = fd;
          // socketList.push_back (sock_con);
          sock->state = SS_LISTEN;
          sock_con->state= SS_CONNECTED;
          sock_con->expectedseqnum = seq;
          // listenList.push_back (sock_con);
          listenList.insert (listenList.begin(), sock_con);
          // listenList.erase (std::find (listenList.begin(), listenList.end(), sock));
          returnSystemCall (sock->syscallUUID, sock_con->fd);
          return;
        }
        return;
      }
DATA:
      if (sock->state == SS_CONNECTED)
      {
        if (flag == ACK)
        {
          if (ip_length > 40)
          {
            if (sock->expectedseqnum == seq)
            {
              if (sock->read_waiting == nullptr)
              {
                memcpy ((char*)sock->receive_window + sock->rw_size, payload, ip_length - 40);
                sock->rw_size += ip_length - 40;
                sock->expectedseqnum = seq + ip_length - 40;
                Packet pkt = createPacket (sock, sock->seq, sock->expectedseqnum, nullptr, 0, ACK);
                sendPacket ("IPv4", std::move(pkt));
                return;
              }
              else
              {
                int size;
                if (ip_length - 40 > sock->count)
                {
                  size = sock->count;
                  sock->count = 0;
                  memcpy (sock->read_waiting, payload, size);
                  sock->expectedseqnum = seq + ip_length - 40;
                  Packet pkt = createPacket (sock, sock->seq, sock->expectedseqnum, nullptr, 0, ACK);
                  sendPacket ("IPv4", std::move(pkt));
                  sock->read_waiting = nullptr;
                  returnSystemCall (sock->syscallUUID, size);

                  memcpy (sock->receive_window + sock->rw_size, (char *)payload + size, ip_length - 40 - size);
                  sock->rw_size += ip_length - 40 - size;
                  return;
                }
                else
                {
                  int size = ip_length - 40 > sock->count ? sock->count : ip_length - 40;
                  sock->count = 0;
                  memcpy (sock->read_waiting, payload, size);
                  sock->expectedseqnum = seq + ip_length - 40;
                  Packet pkt = createPacket (sock, sock->seq, sock->expectedseqnum, nullptr, 0, ACK);
                  sendPacket ("IPv4", std::move(pkt));
                  sock->read_waiting = nullptr;
                  returnSystemCall (sock->syscallUUID, size);
                  return;
                }
                return;
              }
            }
            else
            {
              Packet pkt = createPacket (sock, sock->seq, sock->expectedseqnum, nullptr, 0, ACK);
              sendPacket ("IPv4", std::move(pkt)); 
              return;
            }
            return;
          }
          else
          {
            int i = sock->sn_base;
            uint32_t tseq;
            for (i = sock->sn_base; i < sock->sn_nextseqnum; i++)
            {
              sock->packet_queue[i].readData (38, &tseq, 4);
              tseq = ntohl (tseq);
              if (tseq == ack)
              {
                break;
              }
            }
            sock->sn_base = i;
            while (sock->sn_nextseqnum < (int) sock->packet_queue.size() && sock->sn_nextseqnum < sock->sn_base + sock->window_size)
            {
              sendPacket ("IPv4", std::move(sock->packet_queue[sock->sn_nextseqnum]));
              sock->sn_nextseqnum++;
            }

            if (sock->sn_base == sock->sn_nextseqnum)
            {
              Socket *sock_it, *s;
              std::vector <Socket *>::iterator i;
              for (i = socketList.begin(); i != socketList.end(); )
              {
                sock_it = *i;
                if (sock_it->pid == sock->pid && sock_it->fd == sock->fd)
                {
                  s = sock;
                  socketList.erase (i);
                }
                else
                {
                  i++;
                }
              }
              i = std::find (listenList.begin(), listenList.end(), s);
              if (i != listenList.end())
              {
                listenList.erase (i);
              }
              removeFileDescriptor (sock->pid, sock->fd);
              returnSystemCall (sock->close, 1);
              s->packet_queue = std::vector<Packet> ();
              delete s->addr_in_src;
              delete s->addr_in_dst;
              delete s;
            }
            return;
          }        
        }
        return;
      }
    }
  }
}

Packet TCPAssignment::createPacket (Socket *sock, uint8_t flag)
{
  Sockad_in *addr_from = sock -> addr_in_src;
  Sockad_in *addr_to = sock -> addr_in_dst;

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

  uint32_t seq = htonl (sock -> seq);
  uint32_t ack = htonl (sock -> ack);


  pkt.writeData(34 + 4, &seq, 4);
  pkt.writeData(34 + 8, &ack, 4);

  uint8_t head_len = 0x50;
  pkt.writeData(34 + 12, &head_len, 1);
  pkt.writeData(34 + 13, &flag, 1);

  // uint16_t window = htons(51200);
  uint16_t window = htons(51200 - sock->rw_size);
  pkt.writeData(34 + 14, &window, 2);

  uint16_t zero = 0;
  pkt.writeData (34 + 16, &zero, 2);
  uint8_t tcp_seg[20];
  pkt.readData (14 + 20, tcp_seg, sizeof (tcp_seg));
  uint16_t checksum = NetworkUtil::tcp_sum(addr_from_ip, addr_to_ip, tcp_seg, 20);
  checksum = htons(~checksum);
  pkt.writeData(34 + 16, &checksum, 2);

  return pkt;
}

Packet TCPAssignment::createPacket (Socket *sock, uint32_t _seq, uint32_t _ack, const void *buf, uint16_t length, uint8_t flag)
{
  Sockad_in *addr_from = sock -> addr_in_src;
  Sockad_in *addr_to = sock -> addr_in_dst;

  in_addr_t addr_from_ip = (in_addr_t) htonl(addr_from -> sin_addr);
  in_addr_t addr_to_ip = (in_addr_t) htonl(addr_to -> sin_addr);
  in_port_t addr_from_port = (in_port_t) htons(addr_from -> sin_port);
  in_port_t addr_to_port = (in_port_t) htons(addr_to -> sin_port);
  
  Packet pkt(54 + length);
  
  // ip
  uint16_t ip_length = htons(length + 40);
  pkt.writeData (14 + 2, &ip_length, 2);
  pkt.writeData(14 + 12, &addr_from_ip, 4);
  pkt.writeData(14 + 16, &addr_to_ip, 4);
  pkt.writeData(34, &addr_from_port, 2);
  pkt.writeData(34 + 2, &addr_to_port, 2);

  uint32_t seq = htonl (_seq);
  uint32_t ack = htonl (_ack);


  pkt.writeData(34 + 4, &seq, 4);
  pkt.writeData(34 + 8, &ack, 4);

  uint8_t head_len = 0x50;
  pkt.writeData(34 + 12, &head_len, 1);
  pkt.writeData(34 + 13, &flag, 1);

  uint16_t window = htons(51200);
  pkt.writeData(34 + 14, &window, 2);

  uint16_t zero = 0;
  pkt.writeData (34 + 16, &zero, 2);

  if (buf != nullptr && length != 0)
  {
    pkt.writeData (54, buf, length);
    uint8_t tcp_seg[1500];
    pkt.readData (34, tcp_seg, 20 + length);
    uint16_t checksum = NetworkUtil::tcp_sum(addr_from_ip, addr_to_ip, tcp_seg, 20 + length);
    checksum = htons(~checksum);
    pkt.writeData(34 + 16, &checksum, 2);
  }
  else
  {
    uint8_t tcp_seg[20];
    pkt.readData (14 + 20, tcp_seg, sizeof (tcp_seg));
    uint16_t checksum = NetworkUtil::tcp_sum(addr_from_ip, addr_to_ip, tcp_seg, 20);
    checksum = htons(~checksum);
    pkt.writeData(34 + 16, &checksum, 2);
  }

  return pkt;
}

bool TCPAssignment::isMatchingAddr (Socket *sock, uint32_t ip, uint16_t port)
{
  if ((sock->addr_in_src->sin_addr == ip ||
       sock->addr_in_src->sin_addr == INADDR_ANY) &&
      (sock->addr_in_src->sin_port == port))
  {
    return true;
  }
  return false;
}

bool TCPAssignment::isMatchingAddrDst (Socket *sock, uint32_t ip, uint16_t port)
{
  if ((sock->addr_in_dst->sin_addr == ip ||
       sock->addr_in_dst->sin_addr == INADDR_ANY) &&
      (sock->addr_in_dst->sin_port == port))
  {
    return true;
  }
  return false;
}

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
}

void TCPAssignment::syscall_socket (UUID syscallUUID, int pid,
                                   int domain, int type, int protocol)
{
  int fd;
  if ((fd = createFileDescriptor (pid)) == -1)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }

  Socket *sock = new Socket;
  sock->close = -1;
  sock->syscallUUID = syscallUUID;
  sock->fd = fd;
  sock->pid = pid;
  sock->domain = domain;
  sock->type = type;
  sock->protocol = protocol;
  sock->state = SS_FREE;
  sock->seq = 0;
  sock->ack = 0;
  sock->backlog = 0;
  sock->accept_waiting = nullptr;
  sock->read_waiting = nullptr;
  sock->window_size = 10;

  sock->addr_in_src = nullptr;
  sock->addr_in_dst = nullptr;
  sock->incomplete_queue = std::vector <Socket *>();
  sock->complete_queue = std::vector <Socket *>();
  sock->sock_con = nullptr;

  sock->sn = sock->sn_base = sock->sn_nextseqnum = sock->expectedseqnum = 0;
  sock->rw_size = 0;
  sock->read_waiting = nullptr;
  sock->count = 0;
  sock->receive_window = malloc (51200);
  sock->packet_queue = std::vector <Packet> ();

  socketList.push_back (sock);
  returnSystemCall (syscallUUID, fd);
  return;
}

// address: network order
void TCPAssignment::syscall_bind (UUID syscallUUID, int pid,
                                 int fd, struct sockaddr *address,
                                 socklen_t address_len)
{
  Socket *sock = getSocket (pid, fd);
  Sockad_in *_addr = (Sockad_in *) address;
  
  if (sock == nullptr)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }
  if (sock->state != SS_FREE)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }
  
  std::vector <Socket *>::iterator i;
  for (i = socketList.begin(); i != socketList.end(); i++)
  {
    Socket *s = (*i);
    if (s->addr_in_src != NULL)
    {
      if (s->addr_in_src->sin_port == ntohs (_addr->sin_port))
      {
        if (s->addr_in_src->sin_addr == INADDR_ANY
            || s->addr_in_src->sin_addr == ntohl (_addr->sin_addr))
        {
          returnSystemCall (syscallUUID, -1); 
          return;
        }
      }
    }
  }

  // new object not created in socket()
  sock->addr_in_src = new Sockad_in;
  sock->addr_in_dst = new Sockad_in;
  sock->addr_in_src->sin_family = AF_INET;
  sock->addr_in_src->sin_port = ntohs (_addr->sin_port);
  sock->addr_in_src->sin_addr = ntohl (_addr->sin_addr);
  sock->state = SS_BIND;
  returnSystemCall (syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_getsockname (UUID syscallUUID, int pid,
                                        int fd, struct sockaddr *address,
                                        socklen_t *address_len)
{
  Socket *sock = getSocket (pid, fd);
  Sockad_in *_addr = (Sockad_in *) address;

  if (sock == nullptr)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }
  if (sock->addr_in_src == nullptr)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }

  _addr->sin_family = sock->addr_in_src->sin_family;
  _addr->sin_port = htons (sock->addr_in_src->sin_port);
  _addr->sin_addr = htonl (sock->addr_in_src->sin_addr);
  *address_len = sizeof (Sockad_in);
  returnSystemCall (syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_getpeername (UUID syscallUUID, int pid,
                                        int fd, struct sockaddr *address,
                                        socklen_t *address_len)
{
  Socket *sock = getSocket (pid, fd);
  Sockad_in *_addr = (Sockad_in *) address;

  if (sock == nullptr)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }
  if (sock->addr_in_dst == nullptr)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }

  _addr->sin_family = sock->addr_in_dst->sin_family;
  _addr->sin_port = htons (sock->addr_in_dst->sin_port);
  _addr->sin_addr = htonl (sock->addr_in_dst->sin_addr);
  *address_len = sizeof (Sockad_in);
  returnSystemCall (syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, 
                                   int sockfd, int backlog) 
{
  Socket *sock = getSocket (pid, sockfd);

  if (sock == nullptr)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }
  if (sock -> state != SS_BIND)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }

  sock->backlog = backlog;
  listenList.push_back (sock);
  sock->state = SS_LISTEN;
  returnSystemCall (syscallUUID, 0);
  return;
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, 
                                   int fd, struct sockaddr *address, socklen_t *address_len) 
{
  Socket *sock = getSocket (pid, fd);
  Sockad_in *_addr = (Sockad_in *) address;

  if (sock == nullptr)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }
  if (sock->state != SS_LISTEN)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }
  
  // connect after accept
  if (sock->complete_queue.empty())
  {
    sock->state = SS_LISTEN;
    sock->accept_waiting = _addr;
    sock->syscallUUID = syscallUUID;
    return;
  }
  // connect before accept
  else
  {
    Socket *sock_con = sock->complete_queue.front();
    sock->complete_queue.erase (sock->complete_queue.begin());
    sock->sock_con = sock_con;
    _addr->sin_family = AF_INET;
    _addr->sin_port = sock_con->addr_in_dst->sin_port;
    _addr->sin_addr = sock_con->addr_in_dst->sin_addr;
    sock_con->pid = sock->pid;

    int fd;
    if ((fd = createFileDescriptor (sock_con -> pid)) == -1)
    {
      delete sock_con->addr_in_src;
      delete sock_con->addr_in_dst;
      delete sock_con;
      returnSystemCall (sock->syscallUUID, -1);
      return;
    }
    sock_con->fd = fd;
    // socketList.push_back (sock_con);
    socketList.insert (socketList.begin(), sock_con);
    sock->state = SS_LISTEN;
    sock_con->state= SS_CONNECTED;
    // listenList.push_back (sock_con);
    listenList.insert (listenList.begin(), sock_con);
    returnSystemCall(syscallUUID, fd);
    return;
  }
}     

void TCPAssignment::syscall_connect (UUID syscallUUID, int pid,
                                    int sockfd, struct sockaddr *address,
                                    socklen_t address_len)
{
  Socket *sock = getSocket (pid, sockfd);
  Sockad_in *_addr = (Sockad_in *) address;
  Sockad_in *server_addr = new Sockad_in;
  if (sock == nullptr)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }
  if (sock->state > SS_BIND)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }
  if (sock->state == SS_FREE)
  {
    sock->addr_in_src = new Sockad_in;
    sock->addr_in_dst = new Sockad_in;
  }

  // sock->addr_in_dst is already allocated
  server_addr->sin_family = AF_INET;
  server_addr->sin_port = ntohs (_addr->sin_port);
  server_addr->sin_addr = ntohl (_addr->sin_addr);
  sock->addr_in_dst->sin_family = AF_INET;
  sock->addr_in_dst->sin_port = ntohs (_addr->sin_port);
  sock->addr_in_dst->sin_addr = ntohl (_addr->sin_addr);

  if (sock->state == SS_FREE)
  {
    int dst_port;
    in_port_t local_port;
    uint32_t local_ip;
    std::optional<ipv4_t> local_ipv4;
    std::vector <Socket *>::iterator it;
    
    ipv4_t ip_dest;
    // std::memcpy(&ip_dest, (void *) &address_in -> sin_addr, 4);
    ip_dest = NetworkUtil::UINT64ToArray<4>(server_addr -> sin_addr);
    
    // std::optional<ipv4_t> ip = getHost() -> getIPAddr()

    dst_port = getHost() -> getRoutingTable(ip_dest);
    local_ipv4 = this -> getHost() -> getIPAddr(dst_port);
    
    // std::memcpy(&local_ip, (void *) &local_ipv4, 4);
    local_ip = NetworkUtil::arrayToUINT64<4>(local_ipv4.value());

    while (true) {
      int iter = 0;
      local_port = rand() % 65536;
      for (it = socketList.begin(); it != socketList.end(); it++) {
        Socket *socket_temp = (*it);
        if (socket_temp->state == SS_FREE)
        {
          continue;
        }
        if (socket_temp -> addr_in_src -> sin_port == local_port) {
          if (socket_temp -> addr_in_src -> sin_addr == ntohl(INADDR_ANY)
              || socket_temp -> addr_in_src -> sin_addr == local_ip) 
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

    sock->addr_in_src->sin_family = AF_INET;
    sock->addr_in_src->sin_port = ntohs(local_port);
    sock->addr_in_src->sin_addr = ntohl(local_ip);
  }
  
  sock->seq = rand();
  sock->ack = 0;

  Packet pkt = createPacket (sock, SYN);
  listenList.push_back (sock);
  sock->syscallUUID = syscallUUID;
  sock->state = SS_SYNSENT;
  // for syscallreturn (connect, ...)
  sendPacket ("IPv4", std::move (pkt));
  return;
}

void TCPAssignment::syscall_close (UUID syscallUUID, int pid,
                                  int fd)
{
  Socket *sock = getSocket (pid, fd);
  Socket *s;

  if (sock == nullptr)
  {
    returnSystemCall (syscallUUID, -1);
    return;
  }

  if (sock->sn_base < sock->sn_nextseqnum)
  {
    sock->close = syscallUUID;
    return;
  }

  std::vector <Socket *>::iterator i;
  for (i = socketList.begin(); i != socketList.end(); )
  {
    sock = *i;
    if (sock->pid == pid && sock->fd == fd)
    {
      s = sock;
      socketList.erase (i);
    }
    else
    {
      i++;
    }
  }
  i = std::find (listenList.begin(), listenList.end(), s);
  if (i != listenList.end())
  {
    listenList.erase (i);
  }

  delete s->addr_in_src;
  delete s->addr_in_dst;
  delete s;
  removeFileDescriptor (pid, fd);
  returnSystemCall (syscallUUID, 1);
  return;
}

void TCPAssignment::syscall_read (UUID syscallUUID, int pid,
                                  int sockfd, void *buf, size_t count) 
{
  Socket *sock = getSocket(pid, sockfd);

  if (sock == nullptr) {
    returnSystemCall(syscallUUID, -1);
    return;
  }

  if (count == 0) {
    returnSystemCall(syscallUUID, 0);
    return;
  }

  if (sock->rw_size <= 0)
  {
    if (sock->read_waiting != nullptr)
    {
      returnSystemCall (syscallUUID, 0);
      return;
    }
    sock->read_waiting = buf;
    sock->syscallUUID = syscallUUID;
    sock->count = count;
    return;
  }

  else
  {
    int size = sock->rw_size > (int)count ? (int)count : sock->rw_size;
    memcpy (buf, sock->receive_window, size);
    memmove (sock->receive_window, (char *)sock->receive_window + size, sock->rw_size - size);
    sock->rw_size -= size;
    returnSystemCall (syscallUUID, size);
    return;
  }
}

void TCPAssignment::syscall_write (UUID syscallUUID, int pid,
                                  int sockfd, const void *buf, size_t count) 
{
  Socket *sock = getSocket(pid, sockfd);

  if (sock == nullptr) {
    returnSystemCall(syscallUUID, -1);
    return;
  }

  if (count == 0)  {
    returnSystemCall(syscallUUID, 0);
    return;
  }

  int cnt = count, size = 0, pos = 0;
  int packet_count = 0;
  while (cnt > 0)
  {
    size = cnt > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : cnt;
    Packet pkt = createPacket (sock, sock->seq, sock->ack, (char *)buf + pos, size, ACK);
    sock->packet_queue.push_back (pkt);
    packet_count++;
    cnt -= size;
    pos += size;
    sock->seq += size;
    if (packet_count > sock->window_size)
    {
      break;
    }
  }

  auto i = sock->sn_base;
  while (i < (int) sock->packet_queue.size() && i < sock->sn_base + sock->window_size)
  {
    if (i >= sock->sn_nextseqnum)
    {
      sendPacket ("IPv4", std::move(sock->packet_queue[i]));
      sock->sn_nextseqnum++;
    }
    i++;
  }
  returnSystemCall (syscallUUID, count);
  return;
}

} // namespace E
