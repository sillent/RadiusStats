/* 
 * File:   callback_sniff.h
 * Author: santa
 *
 * Created on 10 ноября 2014 г., 11:14
 */
static unsigned long long rad_auth_req=0;
static unsigned long long rad_auth_res=0;
static unsigned long long rad_auth_rej=0;
static unsigned long long rad_acct_req=0;
static unsigned long long rad_acct_res=0;
    
#define SERVER_PORT 5005
#ifndef CALLBACK_SNIFF_H
#define	CALLBACK_SNIFF_H
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <sys/types.h>
#include <arpa/inet.h>


#define SIZE_ETH_IP_UDP 42
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6

#define AUTH_REQ 1
#define AUTH_RES 2
#define AUTH_REJ 3
#define ACCT_REQ 4
#define ACCT_RES 5
 
u_int size_ip;
u_int size_udp_h;
u_int size_udp;
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};
struct sniff_ip {
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_ident;
    u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
    u_char ip_ttl;
    u_char ip_proto;
    u_short ip_checksum;
    struct in_addr ip_src,ip_dst;
};
#define IP_HL(ip) (((ip)->ip_vhl)&0x0f)  
#define IP_V(ip) (((ip)->ip_vhl)>>4)

struct sniff_udp {
  u_short udp_sport;
  u_short udp_dport;
  u_short udp_len;
  u_short udp_checksum;
};
#define UDP_HL  8
struct sniff_radius {
  u_char r_code;
  u_char *payload;
};

#define BE_2_LE(data) ntohs((uint16_t)data)

void callback_sniff(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *bytes);
void sendToServer(int type, long long count);
#endif	/* CALLBACK_SNIFF_H */

