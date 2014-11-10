/* 
 * File:   sniffer.h
 * Author: santa
 *
 * Created on 7 ноября 2014 г., 15:23
 */

#ifndef SNIFFER_H
#define	SNIFFER_H

#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>


pcap_if_t* findDevice();
pcap_t* sniffInit(char* iface, char *filter);
pcap_t* openDeviceToSniff(pcap_if_t *device);
int compileFilterToHandler(char *filter, pcap_t *handle);
int startSniff(pcap_t *handle);
#endif	/* SNIFFER_H */

