//
// Created by ghost on 20/11/2021.
//

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <xalloc.h>

#include "logger.h"
#include "module_isatap.h"
#include "packet.h"

// suppress snprintf
#pragma GCC diagnostic ignored "-Wformat"

static probe_module_t module_isatap;

//////////////////
// send functions
//////////////////
static int isatap_thread_initialize(void *buf, macaddr_t *src,
				    macaddr_t *gw,
				    UNUSED port_n_t src_port,
				    UNUSED void **arg_ptr)
{
	struct ether_header *eth = buf;
	struct ip *ip_header = (struct ip *) (&eth[1]);
	struct ip6_hdr *ipv6 = (struct ip6_hdr *) (&ip_header[1]);
	struct nd_router_solicit *rs = (struct nd_router_solicit *) (&ipv6[1]);

	memset(buf, 0, MAX_PACKET_SIZE);
	make_eth_header(eth, src, gw);
	make_ip_header(ip_header, IPPROTO_IPV6, htons(sizeof(struct ip) +
						      sizeof(struct ip6_hdr) +
						      sizeof(struct nd_router_solicit)));

	// version(4), traffic class(8), flow id(20)
	// 6_00_00000
	ipv6->ip6_flow = 0x60000000;
	ipv6->ip6_plen = htons(sizeof(struct nd_router_solicit));
	ipv6->ip6_nxt = IPPROTO_ICMPV6;
	// default hops
	// reference: https://datatracker.ietf.org/doc/html/rfc4861#section-4.1
	ipv6->ip6_hops = MAXTTL;

	// router solicitation message
	rs->nd_rs_type = ND_ROUTER_SOLICIT;
	rs->nd_rs_code = 0;
	rs->nd_rs_hdr.icmp6_data32[0] = 0;

	return EXIT_SUCCESS;
}

static int isatap_make_packet(void *buf, size_t *buf_len,
			      ipaddr_n_t src_ip, ipaddr_n_t dst_ip, uint8_t ttl,
			      UNUSED uint32_t *validation,
			      UNUSED int probe_num, UNUSED void *arg)
{
	struct ether_header *eth = buf;
	struct ip *ip_header = (struct ip *) (&eth[1]);
	struct ip6_hdr *ipv6 = (struct ip6_hdr *) (&ip_header[1]);
	struct nd_router_solicit *rs = (struct nd_router_solicit *) (&ipv6[1]);

	struct icmp6_chksum_st {
		struct in6_addr ip6_src;      /* source address */
		struct in6_addr ip6_dst;      /* destination address */
		uint32_t ip6_payloadlen;   /* payload length */
		uint16_t zeros_part1;
		uint8_t zeros_part2;
		uint8_t nxt_hdr;
		struct nd_router_solicit rs;
	} cksum;
	memset(&cksum, 0, sizeof(struct icmp6_chksum_st));

	// ipv4
	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	ip_header->ip_ttl = ttl;

	// ipv6
	ipv6->ip6_src.s6_addr32[0] = htonl(0xfe800000);
	ipv6->ip6_src.s6_addr32[1] = htonl(0x00000000);
	ipv6->ip6_src.s6_addr32[2] = htonl(0x02005efe);
	ipv6->ip6_src.s6_addr32[3] = src_ip;

	ipv6->ip6_dst.s6_addr32[0] = htonl(0xfe800000);
	ipv6->ip6_dst.s6_addr32[1] = htonl(0x00000000);
	ipv6->ip6_dst.s6_addr32[2] = htonl(0x00005efe);
	ipv6->ip6_dst.s6_addr32[3] = dst_ip;

	memcpy(&cksum.ip6_src, &ipv6->ip6_src, sizeof(struct in6_addr));
	memcpy(&cksum.ip6_dst, &ipv6->ip6_dst, sizeof(struct in6_addr));
	cksum.ip6_payloadlen = ipv6->ip6_plen;
	cksum.nxt_hdr = ipv6->ip6_nxt;
	memcpy(&cksum.rs, rs, sizeof(struct nd_router_solicit));

	rs->nd_rs_cksum = 0;
	rs->nd_rs_cksum = icmp_checksum((unsigned short *)&cksum, sizeof(struct icmp6_chksum_st));

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *)ip_header);
	*buf_len = sizeof(struct ether_header) +
		   sizeof(struct ip) +
		   sizeof(struct ip6_hdr) +
		   sizeof(struct nd_router_solicit);
	return EXIT_SUCCESS;
}

// dry run (debug)
static void isatap_print_packet(FILE *fp, void *buf)
{
	struct ether_header *eth = buf;
	struct ip *iph = (struct ip *) (&eth[1]);
	struct ip6_hdr *ipv6 = (struct ip6_hdr *) (&iph[1]);
	struct nd_router_solicit *rs = (struct nd_router_solicit *) (&ipv6[1]);

	fprintf(fp,
		"icmpv6 { type: %u | code: %u | checksum: %#04X } \n",
		rs->nd_rs_type, rs->nd_rs_code, rs->nd_rs_cksum);
	fprintf(fp,
		"ipv6 { id: %#08X "
		   "| payload length: %u | next header: %u | hop limit: %u "
		   "| src: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X "
		   "| dst: %04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X }\n",
		ipv6->ip6_flow, ntohs(ipv6->ip6_plen), ipv6->ip6_nxt, ipv6->ip6_hops,
		ipv6->ip6_src.s6_addr16[0], ipv6->ip6_src.s6_addr16[1],
		ipv6->ip6_src.s6_addr16[2], ipv6->ip6_src.s6_addr16[3],
		ipv6->ip6_src.s6_addr16[4], ipv6->ip6_src.s6_addr16[5],
		ipv6->ip6_src.s6_addr16[6], ipv6->ip6_src.s6_addr16[7],
		ipv6->ip6_dst.s6_addr16[0], ipv6->ip6_dst.s6_addr16[1],
		ipv6->ip6_dst.s6_addr16[2], ipv6->ip6_dst.s6_addr16[3],
		ipv6->ip6_dst.s6_addr16[4], ipv6->ip6_dst.s6_addr16[5],
		ipv6->ip6_dst.s6_addr16[6], ipv6->ip6_dst.s6_addr16[7]);
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, eth);
	fprintf(fp, PRINT_PACKET_SEP);
}

//////////////////
// recv functions
//////////////////
static int isatap_validate_packet(const struct ip *ip_hdr, uint32_t len,
				  uint32_t *src_ip, UNUSED uint32_t *validation)
{

	const uint32_t src_ipaddr = *src_ip;
	struct ip6_hdr *ipv6;
	struct nd_router_advert *ra;
	struct nd_opt_hdr *opt;
	struct nd_opt_hdr *c_opt;
	int has_prefix = 0;
	size_t opt_offset;
	size_t opt_len;

	if (ip_hdr->ip_p != IPPROTO_IPV6) {
		return PACKET_INVALID;
	}

	if (ip_hdr->ip_dst.s_addr != src_ipaddr) {
		return PACKET_INVALID;
	}

	// options are required
	if ((4 * ip_hdr->ip_hl + sizeof(struct ip6_hdr)) +
		sizeof(struct nd_router_advert) >= len) {
		return PACKET_INVALID;
	}

	ipv6 = (struct ip6_hdr *) ((char *) ip_hdr + 4 * ip_hdr->ip_hl);
	if (ipv6->ip6_nxt != IPPROTO_ICMPV6) {
		return PACKET_INVALID;
	}

	// allowed prefix:
	// ND_OPT_SOURCE_LINKADDR: 4 * c_opt->nd_opt_len
	// ND_OPT_TARGET_LINKADDR: 4 * c_opt->nd_opt_len
	// ND_OPT_PREFIX_INFORMATION: 4 * c_opt->nd_opt_len + 16(prefix)
	// ND_OPT_MTU: 4 * c_opt->nd_opt_len + 4(mtu)
	ra = (struct nd_router_advert *) &ipv6[1];
	if (ra->nd_ra_type != ND_ROUTER_ADVERT) {
		return PACKET_INVALID;
	}

	c_opt = opt = (struct nd_opt_hdr *) &ra[1];
	opt_len = len -
		  (4 * ip_hdr->ip_hl +
		   sizeof(struct ip6_hdr) +
		   sizeof(struct nd_router_advert));
	opt_offset = 0;
	while (1) {
		if (opt_offset >= opt_len) break;

		if (c_opt->nd_opt_type == ND_OPT_PREFIX_INFORMATION) {
			has_prefix = 1;
			break;
		} else if (c_opt->nd_opt_type == ND_OPT_MTU) {
			opt_offset += 4;
		}

		opt_offset += 4 * c_opt->nd_opt_len;
		c_opt = (struct nd_opt_hdr *) ((char *) opt + opt_offset);
	}

	if (opt_offset > opt_len) return PACKET_INVALID;
	if (!has_prefix) return PACKET_INVALID;

	return PACKET_VALID;
}

// field related settings

#define FIELD_IP4_SADDR "ipv4_saddr"
#define FIELD_IP4_DADDR "ipv4_daddr"
#define FIELD_IP6_SADDR "ipv6_saddr"
#define FIELD_IP6_DADDR "ipv6_daddr"
#define FIELD_ICMP_TYPE "icmp_type"
#define FIELD_ICMP_CODE "icmp_code"
#define FIELD_ICMP_RA_CURHOP "icmp_ra_curhop"
#define FIELD_ICMP_RA_FLAG_M "icmp_ra_m"
#define FIELD_ICMP_RA_FLAG_O "icmp_ra_o"
#define FIELD_ICMP_RA_LIFETIME "icmp_ra_life"
#define FIELD_ICMP_RA_REACHABLE "icmp_ra_reach"
#define FIELD_ICMP_RA_RETRANS "icmp_ra_retrans"
#define FIELD_ISATAP_PREFIX "isatap_prefix"
#define FIELD_ISATAP_PREFIX_LEN "isatap_prefix_len"
#define FIELD_ISATAP_MTU "isatap_mtu"

#define NEED_FREE 1

// upon success validation
static void isatap_process_packet(const u_char *packet, UNUSED uint32_t len,
				  fieldset_t *fs,
				  UNUSED uint32_t *validation,
				  UNUSED struct timespec ts)
{

	struct ip *ipv4 = (struct ip *)&packet[sizeof(struct ether_header)];
	struct ip6_hdr *ipv6 =
	    (struct ip6_hdr *)((char *)ipv4 + 4 * ipv4->ip_hl);

	struct nd_router_advert *ra = (struct nd_router_advert *) &ipv6[1];

	struct nd_opt_hdr *opt = (struct nd_opt_hdr *) &ra[1];
	struct nd_opt_hdr *c_opt = opt;
	struct nd_opt_prefix_info *prefix;
	struct nd_opt_mtu *mtu = NULL;
	size_t opt_offset;
	size_t opt_len;

	char *ipv4_saddr, *ipv4_daddr;
	char *ipv6_saddr = xmalloc(48),
	     *ipv6_daddr = xmalloc(48),
	     *prefix_str = xmalloc(48);

	// since this is a response package, we have to revert src and dst
	ipv4_daddr = make_ip_str(ipv4->ip_src.s_addr);
	ipv4_saddr = make_ip_str(ipv4->ip_dst.s_addr);
	snprintf(ipv6_daddr, 48, "%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",
		ipv6->ip6_src.s6_addr16);
	snprintf(ipv6_saddr, 48, "%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",
		ipv6->ip6_dst.s6_addr16);

	fs_add_string(fs, FIELD_IP4_SADDR, ipv4_saddr, NEED_FREE);
	fs_add_string(fs, FIELD_IP4_DADDR, ipv4_daddr, NEED_FREE);
	fs_add_string(fs, FIELD_IP6_SADDR, ipv6_saddr, NEED_FREE);
	fs_add_string(fs, FIELD_IP6_DADDR, ipv6_daddr, NEED_FREE);

	fs_add_uint64(fs, FIELD_ICMP_TYPE, ra->nd_ra_type);
	fs_add_uint64(fs, FIELD_ICMP_CODE, ra->nd_ra_code);
	fs_add_uint64(fs, FIELD_ICMP_RA_CURHOP, ra->nd_ra_curhoplimit);
	fs_add_bool(fs, FIELD_ICMP_RA_FLAG_M, ra->nd_ra_flags_reserved & ND_RA_FLAG_MANAGED);
	fs_add_bool(fs, FIELD_ICMP_RA_FLAG_O, ra->nd_ra_flags_reserved & ND_RA_FLAG_OTHER);

	opt_len = len -
		  (4 * ipv4->ip_hl +
		   sizeof(struct ip6_hdr) +
		   sizeof(struct nd_router_advert));
	opt_offset = 0;
	while (1) {
		if (opt_offset >= opt_len) break;

		if (c_opt->nd_opt_type == ND_OPT_PREFIX_INFORMATION) {
			prefix = (struct nd_opt_prefix_info *) c_opt;
			snprintf(prefix_str, 48, "%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",
				prefix->nd_opt_pi_prefix.s6_addr16);
			fs_add_string(fs, FIELD_ISATAP_PREFIX, prefix_str, NEED_FREE);
			fs_add_uint64(fs, FIELD_ISATAP_PREFIX_LEN, prefix->nd_opt_pi_prefix_len);

			opt_offset += 16;
		} else if (c_opt->nd_opt_type == ND_OPT_MTU) {
			mtu = (struct nd_opt_mtu *) c_opt;
			fs_add_uint64(fs, FIELD_ISATAP_MTU, mtu->nd_opt_mtu_mtu);
			opt_offset += 4;
		}

		opt_offset += 4 * c_opt->nd_opt_len;
		c_opt = (struct nd_opt_hdr *) ((char *) opt + opt_offset);
	}

	if (!mtu) {
		fs_add_null(fs, FIELD_ISATAP_MTU);
	}

	fs_add_constchar(fs, "classification", "isatap response");
	fs_add_bool(fs, "success", 1);
}

static fielddef_t fields[] = {
    {.name = FIELD_IP4_SADDR, .type = "string", .desc = "ipv4 source ip address"},
    {.name = FIELD_IP4_DADDR, .type = "string", .desc = "ipv4 destination ip address"},
    {.name = FIELD_IP6_SADDR, .type = "string", .desc = "ipv6 source ip address"},
    {.name = FIELD_IP6_DADDR, .type = "string", .desc = "ipv6 destination ip address"},
    {.name = FIELD_ICMP_TYPE, .type = "int", .desc = "icmp message type"},
    {.name = FIELD_ICMP_CODE, .type = "int", .desc = "icmp message sub type code"},
    {.name = FIELD_ICMP_RA_CURHOP, .type = "int", .desc = "cur hop limit"},
    {.name = FIELD_ICMP_RA_FLAG_M, .type = "bool", .desc = "managed address configuration"},
    {.name = FIELD_ICMP_RA_FLAG_O, .type = "bool", .desc = "other configuration"},
    {.name = FIELD_ICMP_RA_LIFETIME, .type = "int", .desc = "router lifetime"},
    {.name = FIELD_ICMP_RA_REACHABLE, .type = "int", .desc = "reachable time"},
    {.name = FIELD_ICMP_RA_RETRANS, .type = "int", .desc = "retransmit timer"},
    {.name = FIELD_ISATAP_MTU, .type = "int", .desc = "isatap mtu"},
    {.name = FIELD_ISATAP_PREFIX, .type = "string", .desc = "isatap prefix"},
    {.name = FIELD_ISATAP_PREFIX_LEN, .type = "int", .desc = "isatap prefix length"},
    CLASSIFICATION_SUCCESS_FIELDSET_FIELDS,
};

static probe_module_t module_isatap = {
    .name = "isatap",
    .max_packet_length =
	sizeof(struct ip) + sizeof(struct ip6_hdr) + sizeof(struct nd_router_solicit),
    .pcap_filter = "icmp6[icmp6type] = icmp6-routeradvert",
    .pcap_snaplen = 1500,
    .port_args = 0,
    .global_initialize = NULL,
    .thread_initialize = isatap_thread_initialize,
    .make_packet = isatap_make_packet,
    .print_packet = isatap_print_packet,
    .validate_packet = isatap_validate_packet,
    .process_packet = isatap_process_packet,
    .close = NULL,
    .output_type = OUTPUT_TYPE_STATIC,
    .fields = fields,
    .numfields = sizeof(fields) / sizeof(fields[0]),
    .helptext =
	"Probe module that sends isatap protocol packets to detect isatap relay."
};

probe_module_t *MODULE_ISATAP() { return &module_isatap; }
