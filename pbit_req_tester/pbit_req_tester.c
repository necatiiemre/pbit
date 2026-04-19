// pbit_req_tester — standalone raw-socket tool to send PBIT REQUEST packets
// to the VMC over AFDX-style framing (ARINC 664 VL-ID in DST MAC).
//
// Purpose: isolate the request-format question. No DPDK, no PRBS, no warmup —
// just build one packet, send it, optionally repeat. Lets us toggle trailing
// sequence bytes (0 / 1 / 8) to empirically find what the VMC accepts.
//
// Build:   make
// Run:     sudo ./pbit_req_tester -i eno12409 -v 0x000F
//
// Flags:
//   -i <iface>         Egress interface name (required)
//   -v <vl_id_hex>     VL-ID (e.g. 0x000F for VS, 0x000C for FLCS)
//   --vlan <id>        Insert 802.1Q tag with given VID (omit = untagged)
//   --vlan-prio <n>    VLAN PCP (0..7, default 0)
//   --seq-tail <0|1|8> Append trailing sequence bytes after PBIT header
//                        0 = nothing (default)
//                        1 = one byte (DTN_SEQ style)
//                        8 = uint64_t (host endian, like PRBS payloads)
//   --seq <value>      Trailing seq start value (default 0)
//   --seq-head         Put 8-byte seq at START of payload instead of tail
//   -n <count>         Number of packets to send (default 1)
//   --interval <ms>    Inter-packet interval in ms (default 0)
//   --src-mac <hex>    Override source MAC (default 02:00:00:00:00:20)
//   --dst-mac <hex>    Override full dst MAC (default 03:00:00:00:<VL-BE>)
//   --src-ip <a.b.c.d> Override source IP  (default 10.0.0.0)
//   --dst-ip <a.b.c.d> Override dest IP    (default 224.224.<VLh>.<VLl>)
//   --src-port <n>     UDP source port      (default 100)
//   --dst-port <n>     UDP dest port        (default 100)
//   --msg-len <n>      PBIT header.message_len value (default 11)
//   --verbose          Hex dump the outgoing packet
//   -h / --help        Print help

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define ETH_P_8021Q_LOCAL   0x8100
#define PBIT_MSG_ID_REQUEST 0x32   // 50

// ---------- helpers ----------
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

static int parse_mac(const char *s, uint8_t mac[6])
{
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)v[i];
    return 0;
}

static void hex_dump(const uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        printf("%02X ", buf[i]);
        if ((i & 0x0F) == 0x0F) printf("\n");
    }
    if (n & 0x0F) printf("\n");
}

static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s -i <iface> -v <vl_id_hex> [options]\n"
        "  -i <iface>              egress interface (e.g. eno12409)\n"
        "  -v <vl_id_hex>          VL-ID (e.g. 0x000F)\n"
        "  --vlan <id>             insert 802.1Q tag with VID\n"
        "  --vlan-prio <n>         VLAN PCP 0..7 (default 0)\n"
        "  --seq-tail <0|1|8>      append trailing seq bytes (default 0)\n"
        "  --seq <value>           trailing seq start value (default 0)\n"
        "  --seq-head              8B seq at payload head instead of tail\n"
        "  -n <count>              number of packets (default 1)\n"
        "  --interval <ms>         inter-packet delay (default 0)\n"
        "  --src-mac XX:...        src MAC override\n"
        "  --dst-mac XX:...        dst MAC override\n"
        "  --src-ip  a.b.c.d       src IP override\n"
        "  --dst-ip  a.b.c.d       dst IP override\n"
        "  --src-port <n>          UDP src port (default 100)\n"
        "  --dst-port <n>          UDP dst port (default 100)\n"
        "  --msg-len  <n>          PBIT message_len field (default 11)\n"
        "  --verbose               hexdump outgoing packet\n"
        "  -h / --help             this help\n", argv0);
}

int main(int argc, char **argv)
{
    // Defaults
    const char *iface      = NULL;
    int         vl_id      = -1;
    int         vlan_id    = -1;
    int         vlan_prio  = 0;
    int         seq_tail   = 0;       // 0/1/8
    bool        seq_head   = false;
    uint64_t    seq_value  = 0;
    int         count      = 1;
    int         interval_ms = 0;
    uint8_t     src_mac[6] = {0x02,0x00,0x00,0x00,0x00,0x20};
    bool        src_mac_set = true;
    uint8_t     dst_mac[6] = {0x03,0x00,0x00,0x00,0x00,0x00};
    bool        dst_mac_override = false;
    uint32_t    src_ip     = (10u<<24);                     // 10.0.0.0
    uint32_t    dst_ip     = 0;                             // will derive from VL-ID
    bool        dst_ip_override = false;
    uint16_t    src_port   = 100;
    uint16_t    dst_port   = 100;
    uint16_t    msg_len    = 11;
    bool        verbose    = false;

    static struct option long_opts[] = {
        {"vlan",       required_argument, 0, 1001},
        {"vlan-prio",  required_argument, 0, 1002},
        {"seq-tail",   required_argument, 0, 1003},
        {"seq",        required_argument, 0, 1004},
        {"seq-head",   no_argument,       0, 1005},
        {"interval",   required_argument, 0, 1006},
        {"src-mac",    required_argument, 0, 1007},
        {"dst-mac",    required_argument, 0, 1008},
        {"src-ip",     required_argument, 0, 1009},
        {"dst-ip",     required_argument, 0, 1010},
        {"src-port",   required_argument, 0, 1011},
        {"dst-port",   required_argument, 0, 1012},
        {"msg-len",    required_argument, 0, 1013},
        {"verbose",    no_argument,       0, 1014},
        {"help",       no_argument,       0, 'h'},
        {0,0,0,0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:v:n:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': iface = optarg; break;
        case 'v': vl_id = (int)strtol(optarg, NULL, 0); break;
        case 'n': count = atoi(optarg); break;
        case 'h': usage(argv[0]); return 0;
        case 1001: vlan_id   = atoi(optarg); break;
        case 1002: vlan_prio = atoi(optarg) & 7; break;
        case 1003: seq_tail  = atoi(optarg);
                   if (seq_tail != 0 && seq_tail != 1 && seq_tail != 8) {
                       fprintf(stderr, "--seq-tail must be 0, 1 or 8\n");
                       return 2;
                   } break;
        case 1004: seq_value = strtoull(optarg, NULL, 0); break;
        case 1005: seq_head  = true; break;
        case 1006: interval_ms = atoi(optarg); break;
        case 1007: if (parse_mac(optarg, src_mac)) { fprintf(stderr,"bad src-mac\n"); return 2; }
                   src_mac_set = true; break;
        case 1008: if (parse_mac(optarg, dst_mac)) { fprintf(stderr,"bad dst-mac\n"); return 2; }
                   dst_mac_override = true; break;
        case 1009: { struct in_addr a;
                     if (!inet_aton(optarg, &a)) { fprintf(stderr,"bad src-ip\n"); return 2; }
                     src_ip = ntohl(a.s_addr); break; }
        case 1010: { struct in_addr a;
                     if (!inet_aton(optarg, &a)) { fprintf(stderr,"bad dst-ip\n"); return 2; }
                     dst_ip = ntohl(a.s_addr); dst_ip_override = true; break; }
        case 1011: src_port = (uint16_t)atoi(optarg); break;
        case 1012: dst_port = (uint16_t)atoi(optarg); break;
        case 1013: msg_len  = (uint16_t)atoi(optarg); break;
        case 1014: verbose  = true; break;
        default:   usage(argv[0]); return 2;
        }
    }
    (void)src_mac_set;

    if (!iface || vl_id < 0) { usage(argv[0]); return 2; }
    if (vl_id > 0xFFFF)      { fprintf(stderr,"vl_id out of range\n"); return 2; }

    // Derive defaults from VL-ID
    if (!dst_mac_override) {
        dst_mac[4] = (uint8_t)((vl_id >> 8) & 0xFF);
        dst_mac[5] = (uint8_t)(vl_id & 0xFF);
    }
    if (!dst_ip_override) {
        dst_ip = (224u<<24) | (224u<<16) | ((uint32_t)(vl_id >> 8) << 8) | (uint32_t)(vl_id & 0xFF);
    }

    // -------- Build packet in buffer --------
    uint8_t frame[1518];
    memset(frame, 0, sizeof(frame));
    size_t off = 0;

    // Ethernet
    memcpy(frame + off, dst_mac, 6); off += 6;
    memcpy(frame + off, src_mac, 6); off += 6;
    size_t l2_ethertype_off = off;
    off += 2;   // ethertype written after VLAN decision

    if (vlan_id >= 0) {
        // 0x8100
        frame[l2_ethertype_off    ] = 0x81;
        frame[l2_ethertype_off + 1] = 0x00;
        uint16_t tci = (uint16_t)(((vlan_prio & 7) << 13) | (vlan_id & 0x0FFF));
        frame[off++] = (uint8_t)(tci >> 8);
        frame[off++] = (uint8_t)(tci & 0xFF);
        // inner ethertype = 0x0800
        frame[off++] = 0x08;
        frame[off++] = 0x00;
    } else {
        frame[l2_ethertype_off    ] = 0x08;
        frame[l2_ethertype_off + 1] = 0x00;
    }

    // Build PBIT payload first so we know its length
    uint8_t pbit[64];
    size_t  plen = 0;

    if (seq_head) {
        uint64_t s = seq_value;
        memcpy(pbit + plen, &s, 8); plen += 8;
    }

    // PBIT common header (11 B)
    pbit[plen + 0] = PBIT_MSG_ID_REQUEST;                         // msg_identifier
    pbit[plen + 1] = (uint8_t)((msg_len >> 8) & 0xFF);            // message_len hi (BE)
    pbit[plen + 2] = (uint8_t)( msg_len       & 0xFF);            // message_len lo
    uint64_t ts_be = 0;
    {
        uint64_t ts = now_ns();
        ts_be = ((ts & 0xFF00000000000000ULL) >> 56) |
                ((ts & 0x00FF000000000000ULL) >> 40) |
                ((ts & 0x0000FF0000000000ULL) >> 24) |
                ((ts & 0x000000FF00000000ULL) >>  8) |
                ((ts & 0x00000000FF000000ULL) <<  8) |
                ((ts & 0x0000000000FF0000ULL) << 24) |
                ((ts & 0x000000000000FF00ULL) << 40) |
                ((ts & 0x00000000000000FFULL) << 56);
    }
    memcpy(pbit + plen + 3, &ts_be, 8);
    plen += 11;

    if (seq_tail == 1) {
        pbit[plen++] = (uint8_t)(seq_value & 0xFF);
    } else if (seq_tail == 8) {
        uint64_t s = seq_value;
        memcpy(pbit + plen, &s, 8); plen += 8;
    }

    // IPv4 header (20 B)
    size_t ip_off = off;
    uint8_t *ip = frame + ip_off;
    uint16_t ip_total = (uint16_t)(20 + 8 + plen);
    ip[0] = 0x45;               // ver 4, IHL 5
    ip[1] = 0x00;               // TOS
    ip[2] = (uint8_t)(ip_total >> 8);
    ip[3] = (uint8_t)(ip_total & 0xFF);
    ip[4] = 0; ip[5] = 0;       // ID
    ip[6] = 0; ip[7] = 0;       // flags/frag
    ip[8] = 0x01;               // TTL
    ip[9] = 0x11;               // proto = UDP
    ip[10] = 0; ip[11] = 0;     // checksum (zero, fill later)
    uint32_t src_be = htonl(src_ip);
    uint32_t dst_be = htonl(dst_ip);
    memcpy(ip + 12, &src_be, 4);
    memcpy(ip + 16, &dst_be, 4);
    uint16_t ipcs = ip_checksum(ip, 20);
    ip[10] = (uint8_t)(ipcs & 0xFF);
    ip[11] = (uint8_t)(ipcs >> 8);
    off += 20;

    // UDP header (8 B) — checksum left 0 (allowed for IPv4)
    uint16_t udp_len = (uint16_t)(8 + plen);
    frame[off++] = (uint8_t)(src_port >> 8);
    frame[off++] = (uint8_t)(src_port & 0xFF);
    frame[off++] = (uint8_t)(dst_port >> 8);
    frame[off++] = (uint8_t)(dst_port & 0xFF);
    frame[off++] = (uint8_t)(udp_len  >> 8);
    frame[off++] = (uint8_t)(udp_len  & 0xFF);
    frame[off++] = 0; frame[off++] = 0;    // checksum = 0

    // Payload
    memcpy(frame + off, pbit, plen);
    off += plen;

    size_t frame_len = off;
    if (frame_len < 60) frame_len = 60;   // NIC will pad anyway, zero-pad here too

    // -------- Open raw socket --------
    int sk = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sk < 0) { perror("socket(AF_PACKET)"); return 1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(sk, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); close(sk); return 1; }
    int ifindex = ifr.ifr_ifindex;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_halen    = 6;
    memcpy(sll.sll_addr, dst_mac, 6);

    printf("PBIT request tester\n");
    printf("  iface       : %s (idx %d)\n", iface, ifindex);
    printf("  VL-ID       : 0x%04X\n", vl_id);
    printf("  VLAN        : %s%d\n", vlan_id < 0 ? "off" : "vid=", vlan_id < 0 ? 0 : vlan_id);
    printf("  DST MAC     : %02X:%02X:%02X:%02X:%02X:%02X\n",
           dst_mac[0],dst_mac[1],dst_mac[2],dst_mac[3],dst_mac[4],dst_mac[5]);
    printf("  SRC MAC     : %02X:%02X:%02X:%02X:%02X:%02X\n",
           src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
    {
        struct in_addr a; a.s_addr = htonl(src_ip);
        printf("  SRC IP      : %s:%u\n", inet_ntoa(a), src_port);
        a.s_addr = htonl(dst_ip);
        printf("  DST IP      : %s:%u\n", inet_ntoa(a), dst_port);
    }
    printf("  PBIT msg_id : 0x%02X (50)\n", PBIT_MSG_ID_REQUEST);
    printf("  msg_len     : %u\n", msg_len);
    printf("  seq_head    : %s\n", seq_head ? "yes (8B @ start)" : "no");
    printf("  seq_tail    : %d byte(s)%s\n", seq_tail, seq_tail ? " @ end" : "");
    printf("  seq_value   : %lu (0x%lX)\n", (unsigned long)seq_value, (unsigned long)seq_value);
    printf("  payload len : %zu  (frame %zu)\n", plen, frame_len);
    printf("  count       : %d   interval %d ms\n\n", count, interval_ms);

    if (verbose) {
        printf("-- frame hex (%zu B) --\n", frame_len);
        hex_dump(frame, frame_len);
        printf("-- end --\n\n");
    }

    // -------- Send loop --------
    int sent = 0;
    for (int i = 0; i < count; i++) {
        ssize_t n = sendto(sk, frame, frame_len, 0,
                           (struct sockaddr *)&sll, sizeof(sll));
        if (n < 0) {
            perror("sendto");
            break;
        }
        sent++;
        printf("[%d/%d] sent %zd bytes (seq=%lu)\n",
               i + 1, count, n, (unsigned long)(seq_value + i));

        // Bump seq for next iteration (rewrite into the same buffer)
        uint64_t next_seq = seq_value + i + 1;
        if (seq_tail == 1) {
            frame[off - 1] = (uint8_t)(next_seq & 0xFF);
        } else if (seq_tail == 8) {
            memcpy(frame + off - 8, &next_seq, 8);
        }
        if (seq_head) {
            size_t udp_pl_off = off - plen;
            memcpy(frame + udp_pl_off, &next_seq, 8);
        }

        if (interval_ms > 0 && i + 1 < count) {
            struct timespec ts;
            ts.tv_sec  = interval_ms / 1000;
            ts.tv_nsec = (long)(interval_ms % 1000) * 1000000L;
            nanosleep(&ts, NULL);
        }
    }

    printf("\nDone. Sent %d/%d packet(s).\n", sent, count);
    close(sk);
    return (sent == count) ? 0 : 1;
}
