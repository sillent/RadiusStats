/*
 * File:   sniffer.h
 * Author: Dmitry Ulyanov
 *
 * Created on 7 ноября 2014 г., 15:23
 */

#ifndef SNIFFER_H
#define	SNIFFER_H

#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include "callback_sniff.h"

struct snif_arg_t {
    char *dev;
    char *fil;
};

pcap_if_t* findDevice();
void* sniffInit(void* snif_arg_t);
pcap_t* openDeviceToSniff(pcap_if_t *device);
int compileFilterToHandler(char *filter, pcap_t *handle);
int startSniff(pcap_t *handle);
#endif	/* SNIFFER_H */

