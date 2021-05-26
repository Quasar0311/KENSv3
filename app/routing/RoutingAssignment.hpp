/*
 * E_RoutingAssignment.hpp
 *
 */

#ifndef E_ROUTINGASSIGNMENT_HPP_
#define E_ROUTINGASSIGNMENT_HPP_

#include <E/E_TimerModule.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Port.hpp>
#include <E/Networking/E_RoutingInfo.hpp>
#include <netinet/in.h>

#define RIP_PORT 520
#define RIP_INF 301

namespace E {

constexpr Size MaxCost = 20;
constexpr Size calc_cost_lcm(size_t a) {
  return a == 1 ? 1 : std::lcm(a, calc_cost_lcm(a - 1));
}
constexpr Size CostLCM = calc_cost_lcm(MaxCost);

#ifdef HAVE_PRAGMA_PACK
#pragma pack(push, 1)
#elif !defined(HAVE_ATTR_PACK)
#error "Compiler must support packing"
#endif

struct rip_header_t {
  uint8_t command; // 1 - request, 2 - response, 3,4,5 - obsolete/unused
  uint8_t version; // 1 for RIPv1
  uint16_t zero_0; // must be zero
}
#if defined(HAVE_ATTR_PACK)
__attribute__((packed));
#else
;
#endif

struct rip_entry_t {
  uint16_t address_family; // 2 for IP
  uint16_t zero_1;         // must be zero
  uint32_t ip_addr;        // IPv4 address
  uint32_t zero_2;         // must be zero
  uint32_t zero_3;         // must be zero
  uint32_t metric;         // hop-count (max 15) for RIPv1
}
#if defined(HAVE_ATTR_PACK)
__attribute__((packed));
#else
;
#endif

struct rip_t {
  struct rip_header_t header;
  struct rip_entry_t entries[];
}
#if defined(HAVE_ATTR_PACK)
__attribute__((packed));
#else
;
#endif

class RoutingAssignment : public HostModule,
                          public NetworkModule,
                          private NetworkLog,
                          private TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

public:
  RoutingAssignment(Host *host);

  /**
   * @brief Query cost for a host
   *
   * @param ipv4 querying host's IP address
   * @return cost or -1 for no found host
   */
  Size ripQuery(const ipv4_t &ipv4);

  /**
   * @brief Get cost for local port (link)
   *
   * @param port_num querying port's number
   * @return local link cost
   */
  Size portCost(int port_num) {
    Size bps = this->getHost()->getPort(port_num)->getPortSpeed();
    return CostLCM / bps;
  }

  std::map <uint32_t, std::pair <uint32_t, uint32_t>> routing_table;
  int timer;
  uint32_t lookupRoutingTable (uint32_t ip_addr);
  Packet createPacket (int src_port, uint32_t dst_ip, rip_t* rip, int n);
  void printRoutingTable ();

  virtual void initialize();
  virtual void finalize();
  virtual ~RoutingAssignment();

protected:
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
};

class RoutingAssignmentProvider {
private:
  RoutingAssignmentProvider() {}
  ~RoutingAssignmentProvider() {}

public:
  static HostModule *allocate(Host *host) {
    return new RoutingAssignment(host);
  }
};

} // namespace E

#endif /* E_ROUTINGASSIGNMENT_HPP_ */
