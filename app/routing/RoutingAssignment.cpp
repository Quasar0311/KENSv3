/*
 * E_RoutingAssignment.cpp
 *
 */

#include "RoutingAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_RoutingInfo.hpp>
#include <netinet/in.h>
#include <cerrno>

namespace E {

RoutingAssignment::RoutingAssignment(Host *host)
    : HostModule("UDP", host),
      NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
      NetworkLog(host->getNetworkSystem()), TimerModule(host->getSystem()) {}

RoutingAssignment::~RoutingAssignment() {}

void RoutingAssignment::initialize() {
  int port_size = this->getHost()->getPortCount();
  for (int port_num = 0; port_num < port_size; port_num++)
  {
    routing_table[NetworkUtil::arrayToUINT64<4> (this->getHost()->getIPAddr(port_num).value())] = {0, port_num};
  }
  rip_t *rip = (rip_t *) malloc (sizeof (rip_header_t) +
                                  sizeof (rip_entry_t));
  rip->header.command = 1;
  rip->header.version = 1;
  rip->header.zero_0 = 0;
  rip->entries[0].address_family = 0;
  rip->entries[0].zero_1 = 0;
  rip->entries[0].ip_addr = 0;
  rip->entries[0].zero_2 = 0;
  rip->entries[0].zero_3 = 0;
  rip->entries[0].metric = 16;
  timer = addTimer (NULL,  (E::Time) 30 * 1000 * 1000 * 1000);
  for (int port_num = 0; port_num < port_size; port_num++)
  {
    Packet pkt = createPacket (port_num, 0xffffffff, rip, 1);
    sendPacket ("IPv4", std::move (pkt));
  }
}

void RoutingAssignment::finalize() {}

/**
 * @brief Query cost for a host
 *
 * @param ipv4 querying host's IP address
 * @return cost or -1 for no found host
 */
Size RoutingAssignment::ripQuery(const ipv4_t &ipv4) {
  // Implement below
  uint32_t ip_addr = NetworkUtil::arrayToUINT64<4> (ipv4);
  uint32_t metric = lookupRoutingTable (ip_addr);
  if (metric < RIP_INF)
  {
    return (Size) metric;
  }
  return -1;
}

uint32_t RoutingAssignment::lookupRoutingTable(uint32_t ip_addr)
{
  auto search = routing_table.find (ip_addr);
  if (search != routing_table.end())
  {
    return search->second.first;
  }
  else
  {
    return RIP_INF;
  }
}

Packet RoutingAssignment::createPacket (int src_port, uint32_t dst_ip, rip_t *rip, int n)
{
  int size = 14 + 20 + 8 + sizeof (rip_header_t) + sizeof (rip_entry_t) * n;
  Packet pkt (size);
  int offset = 14;
  
  // IP header
  uint32_t src_ip = htonl ( NetworkUtil::arrayToUINT64<4> (this->getHost()->getIPAddr (src_port).value()));
  dst_ip = htonl (dst_ip);
  pkt.writeData (offset + 12, &src_ip, 4);
  pkt.writeData (offset + 16, &dst_ip, 4);
  offset += 20;

  // UDP datagram header
  int port = htons (RIP_PORT);
  size -= 14 + 20;
  size = htons (size);
  pkt.writeData (offset + 0, &port, 2);
  pkt.writeData (offset + 2, &port, 2);
  pkt.writeData (offset + 4, &size, 2);
  offset += 8;

  // RIP header
  struct rip_header_t rip_header = rip->header;
  pkt.writeData (offset + 0, &(rip_header.command), 1);
  pkt.writeData (offset + 1, &(rip_header.version), 1);
  pkt.writeData (offset + 2, &(rip_header.zero_0), 2);
  offset += 4;

  // RIP entries
  struct rip_entry_t *rip_entry = rip->entries;
  for (int i = 0; i < n; i++)
  {
    uint16_t address_family = htons (rip_entry->address_family);
    uint32_t ip_addr = htonl (rip_entry->ip_addr);
    uint32_t metric = htonl (rip_entry->metric);
    pkt.writeData (offset + 0, &(address_family), 2);
    pkt.writeData (offset + 2, &(rip_entry->zero_1), 2);
    pkt.writeData (offset + 4, &(ip_addr), 4);
    pkt.writeData (offset + 8, &(rip_entry->zero_2), 4);
    pkt.writeData (offset + 12, &(rip_entry->zero_3), 4);
    pkt.writeData (offset + 16, &(metric), 4);
    offset += 20;
    rip_entry++;
  }
  uint16_t checksum;
  uint8_t udp_seg[1500];
  size = ntohs (size);
  pkt.readData (14 + 20, udp_seg, size);
  checksum = NetworkUtil::tcp_sum (src_ip, dst_ip, udp_seg, size);
  checksum = htons (~checksum);
  pkt.writeData (14 + 20 + 6, &checksum, 2);
  return pkt;
}

void RoutingAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Validate a packet
  std::cout << fromModule << std::endl;
  int datagram_size, i;
  uint32_t src_ip, dst_ip;
  packet.readData (14 + 20 + 4, &datagram_size, 2);;
  packet.readData (14 + 12, &src_ip, 4);
  packet.readData (14 + 16, &dst_ip, 4);
  datagram_size = ntohs (datagram_size);
  src_ip = ntohl (src_ip);
  dst_ip = ntohl (dst_ip);
  int n_entry = (datagram_size - 8 - 4) / 20;
  size_t s = datagram_size - 8;
  struct rip_t* rip = (struct rip_t *) malloc (s);
  struct rip_entry_t* entry;

  packet.readData (14 + 20 + 8, rip, s);
  if (rip->header.version <= 0)
  {
    return;
  }
  
  for (i = 0; i < n_entry; i++)
  {
    entry = rip->entries + i;
    entry->address_family = ntohs (entry->address_family);
    entry->ip_addr = ntohl (entry->ip_addr);
    entry->metric = ntohl (entry->metric);
  }

  // Request
  if (rip->header.command == 1)
  {
    if (n_entry == 1 && rip->entries[0].address_family == 0)
    {
      // Send the entire routing table
      int n = routing_table.size();
      rip_t *new_rip = (rip_t *) malloc (sizeof (rip_header_t) +
                                sizeof (rip_entry_t) * n);
      new_rip->header.command = 2;
      new_rip->header.version = 1;
      new_rip->header.zero_0 = 0;
      i = 0;
      for (auto& [ip_addr, metric_port] : routing_table)
      {
        new_rip->entries[i].address_family = 2;
        new_rip->entries[i].zero_1 = 0;
        new_rip->entries[i].ip_addr = ip_addr;
        new_rip->entries[i].zero_2 = 0;
        new_rip->entries[i].zero_3 = 0;
        new_rip->entries[i].metric = metric_port.first;
        i++;
      }
      // Packet pkt = createPacket (this->getHost()->getRoutingTable (NetworkUtil::UINT64ToArray<4> (src_ip)), 0xffffffff, new_rip, n);
      Packet pkt = createPacket (this->getHost()->getRoutingTable (NetworkUtil::UINT64ToArray<4> (src_ip)), 167772417, new_rip, n);
      sendPacket ("IPv4", std::move (pkt));
      return;
    }
    else
    {
      for (i = 0; i < n_entry; i++)
      {
        entry = rip->entries + i;
        assert (entry->address_family == 2);
        entry->metric = lookupRoutingTable (entry->ip_addr);
      }
      rip->header.command = 2;
      Packet pkt = createPacket (this->getHost()->getRoutingTable (NetworkUtil::UINT64ToArray<4> (src_ip)), src_ip, rip, n_entry);
      sendPacket ("IPv4", std::move (pkt));
      return;
    }
    return;
  }

  // Response
  if (rip->header.command == 2)
  {
    for (i = 0; i < n_entry; i++)
    {
      entry = rip->entries + i;
      // Check for neighborness
      // Check entry->ip_addr != my ip_addr
      if (entry->metric >= RIP_INF) continue;
      if (entry->address_family != 2) continue;
      // Check for ip_addr validity
      int port = this->getHost()->getRoutingTable (NetworkUtil::UINT64ToArray<4> (entry->ip_addr));
      uint32_t metric = std::min (metric + portCost (port), (unsigned long) RIP_INF);
      
      if (routing_table.count(entry->ip_addr) <= 0)
      {
        routing_table [entry->ip_addr] = {metric, port};
        cancelTimer (timer);
        timer = addTimer (this->getHost()->getIPAddr (port), (E::Time)30 * 1000 * 1000 * 1000);
        // routing_table.insert ({_ip_addr, std::pair <uint32_t, int> (metric, port)});
        // timeout
        // route update
      }
      else
      {
        if (routing_table[entry->ip_addr].second == port ||
            metric < routing_table[entry->ip_addr].first)
        {
          routing_table [entry->ip_addr] = {metric, port};
          cancelTimer (timer);
          timer = addTimer (this->getHost()->getIPAddr (port), (E::Time)30 * 1000 * 1000 * 1000);
          // routing_table.insert_or_assign ({_ip_addr, std::pair <uint32_t, int> (metric, port)});
          if (metric >= RIP_INF)
          {
            // TODO: deletion
          }
        }
      }
    }
    return;
  }
}
void RoutingAssignment::timerCallback(std::any payload) {
  int n = routing_table.size();
  rip_t *new_rip = (rip_t *) malloc (sizeof (rip_header_t) +
                                sizeof (rip_entry_t) * n);
  int port_size = this->getHost()->getPortCount();
  new_rip->header.command = 2;
  new_rip->header.version = 1;
  new_rip->header.zero_0 = 0;
  int i = 0;
  for (auto& [ip_addr, metric_port] : routing_table)
  {
    new_rip->entries[i].address_family = 2;
    new_rip->entries[i].zero_1 = 0;
    new_rip->entries[i].ip_addr = ip_addr;
    new_rip->entries[i].zero_2 = 0;
    new_rip->entries[i].zero_3 = 0;
    new_rip->entries[i].metric = metric_port.first;
    i++;
  }
  for (int port_num = 0; port_num < port_size; port_num++)
  {
    Packet pkt = createPacket (port_num, 0xffffffff, new_rip, n);
    sendPacket ("IPv4", std::move (pkt));
  }
}

} // namespace E
