#include <string.h>
#include "sniffer.h"

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t* sniffInit(char *iface) {
    pcap_t *handle;
    pcap_if_t *dev;
    dev=findDevice();  
    if (dev==NULL) {
        fprintf(stderr, "Can't find any readable device. Exiting.\n");
        exit(13);
    }
    printf("%s\n",iface);
    while (strcmp(iface, dev->name)) // ищем допустимый интерфейс для прослушки 
    {
        dev=(pcap_if_t*)dev->next;
        if (dev==NULL){
            fprintf(stderr, "Can't find device with name %s\n", iface);
            exit(14);
        }
    }
//    открываем интерфейс на прослушку
    handle=openDeviceToSniff(dev);
    return handle;
}

pcap_if_t* findDevice() {
    pcap_if_t *dev;
    if (pcap_findalldevs(&dev,errbuf)) {
        fprintf(stderr, "Can't find any device. Exiting.\n");
        exit(12);
    }
    
    return dev;
}

pcap_t* openDeviceToSniff(pcap_if_t* device) {
    pcap_t* handle=pcap_open_live(device->name, 1500, 1, 0,errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Can't sniff device %s\n",device);
        exit(15);
    }
    return handle;
}

