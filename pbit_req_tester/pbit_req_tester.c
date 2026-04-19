// pbit_req_tester — standalone raw-socket tool that sends a PBIT REQUEST
// every 10 seconds to the VMC over AFDX-style framing.
//
// Edit the three constants below (IFACE, VL_ID, VLAN_ID), then:
//   make && sudo ./pbit_req_tester
//
// Other knobs (SEQ_TAIL, SEQ_HEAD, INTERVAL_SEC, MSG_LEN) are also at the top
// so the whole config lives in one place.

// ============================================================================
//                         EDIT THESE AND REBUILD
// ============================================================================
#define IFACE          "eno12409"   // egress interface
#define VL_ID          15           // decimal — 15 = VS REQ, 12 = FLCS REQ
#define VLAN_ID        97           // decimal — set to -1 for untagged frame
#define VLAN_PRIO      0            // 802.1Q PCP (0..7)

#define SEQ_TAIL       1            // 0 = no tail, 1 = one byte (DTN_SEQ), 8 = uint64
#define SEQ_HEAD       0            // 1 = also put 8B seq at start of payload
#define SEQ_START      0            // starting DTN_SEQ value

#define MSG_LEN        11           // PBIT header.message_len field
#define INTERVAL_SEC   10           // send one packet every N seconds
#define VERBOSE_DUMP   1            // 1 = hex dump each outgoing packet
// ============================================================================

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define PBIT_MSG_ID_REQUEST 0x32   // 50

static const uint8_t SRC_MAC[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x20 };
static const uint32_t SRC_IP    = (10u << 24);                              // 10.0.0.0
static const uint16_t SRC_PORT  = 100;
static const uint16_t DST_PORT  = 100;

static volatile sig_atomic_t g_stop = 0;
static void on_sigint(int s) { (void)s; g_stop = 1; }

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint16_t ip_checksum(const void *buf, size_t len)
{
    const uint16_t *w = buf;
    uint32_t sum = 0;
    while (len > 1) { sum += *w++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)w;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint64_t bswap64(uint64_t v)
{
    return ((v & 0xFF00000000000000ULL) >> 56) |
           ((v & 0x00FF000000000000ULL) >> 40) |
           ((v & 0x0000FF0000000000ULL) >> 24) |
           ((v & 0x000000FF00000000ULL) >>  8) |
           ((v & 0x00000000FF000000ULL) <<  8) |
           ((v & 0x0000000000FF0000ULL) << 24) |
           ((v & 0x000000000000FF00ULL) << 40) |
           ((v & 0x00000000000000FFULL) << 56);
}

static void hex_dump(const uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        printf("%02X ", buf[i]);
        if ((i & 0x0F) == 0x0F) printf("\n");
    }
    if (n & 0x0F) printf("\n");
}

// Builds the full frame into `frame`, returns total length written.
// `seq_value` is stamped into head / tail zones according to SEQ_HEAD/SEQ_TAIL.
static size_t build_frame(uint8_t *frame, size_t cap, uint64_t seq_value,
                          const uint8_t dst_mac[6], uint32_t dst_ip)
{
    (void)cap;
    size_t off = 0;

    // --- Ethernet ---
    memcpy(frame + off, dst_mac, 6); off += 6;
    memcpy(frame + off, SRC_MAC, 6); off += 6;
    size_t ethertype_off = off;
    off += 2;

    if (VLAN_ID >= 0) {
        frame[ethertype_off    ] = 0x81;   // 0x8100
        frame[ethertype_off + 1] = 0x00;
        uint16_t tci = (uint16_t)(((VLAN_PRIO & 7) << 13) | (VLAN_ID & 0x0FFF));
        frame[off++] = (uint8_t)(tci >> 8);
        frame[off++] = (uint8_t)(tci & 0xFF);
        frame[off++] = 0x08;               // inner ethertype = IPv4
        frame[off++] = 0x00;
    } else {
        frame[ethertype_off    ] = 0x08;   // 0x0800
        frame[ethertype_off + 1] = 0x00;
    }

    // --- Build payload first (need length for IP/UDP) ---
    uint8_t pl[64];
    size_t plen = 0;

    if (SEQ_HEAD) {
        memcpy(pl + plen, &seq_value, 8);
        plen += 8;
    }

    // PBIT common header (11 B)
    pl[plen + 0] = PBIT_MSG_ID_REQUEST;
    uint16_t mlen = (uint16_t)MSG_LEN;
    pl[plen + 1] = (uint8_t)(mlen >> 8);
    pl[plen + 2] = (uint8_t)(mlen & 0xFF);
    uint64_t ts_be = bswap64(now_ns());
    memcpy(pl + plen + 3, &ts_be, 8);
    plen += 11;

#if SEQ_TAIL == 1
    pl[plen++] = (uint8_t)(seq_value & 0xFF);
#elif SEQ_TAIL == 8
    memcpy(pl + plen, &seq_value, 8);
    plen += 8;
#endif

    // --- IPv4 (20 B) ---
    uint8_t *ip = frame + off;
    uint16_t ip_total = (uint16_t)(20 + 8 + plen);
    ip[0] = 0x45;
    ip[1] = 0x00;
    ip[2] = (uint8_t)(ip_total >> 8);
    ip[3] = (uint8_t)(ip_total & 0xFF);
    ip[4] = 0; ip[5] = 0;
    ip[6] = 0; ip[7] = 0;
    ip[8] = 0x01;                          // TTL
    ip[9] = 0x11;                          // UDP
    ip[10] = 0; ip[11] = 0;                // checksum = 0 for now
    uint32_t src_be = htonl(SRC_IP);
    uint32_t dst_be = htonl(dst_ip);
    memcpy(ip + 12, &src_be, 4);
    memcpy(ip + 16, &dst_be, 4);
    uint16_t ipcs = ip_checksum(ip, 20);
    ip[10] = (uint8_t)(ipcs & 0xFF);
    ip[11] = (uint8_t)(ipcs >> 8);
    off += 20;

    // --- UDP (8 B) ---
    uint16_t udp_len = (uint16_t)(8 + plen);
    frame[off++] = (uint8_t)(SRC_PORT >> 8);
    frame[off++] = (uint8_t)(SRC_PORT & 0xFF);
    frame[off++] = (uint8_t)(DST_PORT >> 8);
    frame[off++] = (uint8_t)(DST_PORT & 0xFF);
    frame[off++] = (uint8_t)(udp_len  >> 8);
    frame[off++] = (uint8_t)(udp_len  & 0xFF);
    frame[off++] = 0;                      // UDP checksum = 0 (optional for IPv4)
    frame[off++] = 0;

    // --- Payload ---
    memcpy(frame + off, pl, plen);
    off += plen;

    if (off < 60) off = 60;                // pad to Ethernet minimum
    return off;
}

int main(void)
{
    signal(SIGINT,  on_sigint);
    signal(SIGTERM, on_sigint);

    // --- Derive dest MAC and IP from VL-ID (AFDX convention) ---
    uint8_t dst_mac[6] = {0x03, 0x00, 0x00, 0x00,
                          (uint8_t)((VL_ID >> 8) & 0xFF),
                          (uint8_t)(VL_ID & 0xFF)};
    uint32_t dst_ip = (224u << 24) | (224u << 16)
                    | ((uint32_t)(VL_ID >> 8) << 8)
                    |  (uint32_t)(VL_ID & 0xFF);

    // --- Open raw socket and bind to interface ---
    int sk = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sk < 0) { perror("socket(AF_PACKET)"); return 1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ - 1);
    if (ioctl(sk, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX (check IFACE name)");
        close(sk);
        return 1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_halen    = 6;
    memcpy(sll.sll_addr, dst_mac, 6);

    // --- Print config banner ---
    printf("PBIT request tester (periodic)\n");
    printf("  iface      : %s (idx %d)\n", IFACE, ifr.ifr_ifindex);
    printf("  VL-ID      : 0x%04X\n", VL_ID);
    printf("  VLAN       : %s",
           (VLAN_ID >= 0) ? "tagged" : "untagged");
    if (VLAN_ID >= 0) printf(" (VID=%d PCP=%d)", VLAN_ID, VLAN_PRIO);
    printf("\n");
    printf("  DST MAC    : %02X:%02X:%02X:%02X:%02X:%02X\n",
           dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    {
        struct in_addr a; a.s_addr = htonl(dst_ip);
        printf("  DST IP     : %s:%u\n", inet_ntoa(a), DST_PORT);
    }
    printf("  msg_id/len : 0x%02X / %u\n", PBIT_MSG_ID_REQUEST, MSG_LEN);
    printf("  SEQ_HEAD   : %s\n", SEQ_HEAD ? "yes (8B at start)" : "no");
    printf("  SEQ_TAIL   : %d byte(s)%s\n", SEQ_TAIL, SEQ_TAIL ? " at end" : "");
    printf("  interval   : %d sec (Ctrl+C to stop)\n\n", INTERVAL_SEC);

    uint8_t frame[1518];
    uint64_t seq = SEQ_START;
    int iter = 0;

    while (!g_stop) {
        memset(frame, 0, sizeof(frame));
        size_t flen = build_frame(frame, sizeof(frame), seq, dst_mac, dst_ip);

        ssize_t n = sendto(sk, frame, flen, 0,
                           (struct sockaddr *)&sll, sizeof(sll));
        iter++;

        if (n < 0) {
            perror("sendto");
        } else {
            time_t tt = time(NULL);
            struct tm lt;
            localtime_r(&tt, &lt);
            printf("[%02d:%02d:%02d] #%d  sent %zd B  seq=%lu\n",
                   lt.tm_hour, lt.tm_min, lt.tm_sec,
                   iter, n, (unsigned long)seq);
            if (VERBOSE_DUMP) {
                hex_dump(frame, flen);
                printf("\n");
            }
        }

        seq++;

        // Sleep in 1-sec chunks so Ctrl+C responds quickly
        for (int s = 0; s < INTERVAL_SEC && !g_stop; s++) {
            sleep(1);
        }
    }

    printf("\nStopping. Sent %d packet(s).\n", iter);
    close(sk);
    return 0;
}
