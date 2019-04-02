#include <string.h>
#include "sniffer.h"

char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
bpf_u_int32 net;
bpf_u_int32 mask;
char *devName;
void* sniffInit(void* arg_t) {
    struct snif_arg_t *arg=(struct snif_arg_t *)arg_t;
    pcap_t *handle;
    pcap_if_t *dev;
    dev=findDevice();
    if (dev==NULL) {
        fprintf(stderr, "Can't find any readable device. Exiting.\n");
        exit(13);
    }

//     ищем допустимый интерфейс для прослушки
    while ((strcmp(arg->dev, dev->name))!=0)
    {
        dev=(pcap_if_t*)dev->next;
        if (dev==NULL){
            fprintf(stderr, "Can't find device with name %s\n", arg->dev);
            exit(14);
        }
    }
    devName=dev->name;
//    открываем интерфейс на прослушку
    handle=openDeviceToSniff(dev);
//    компилируем  и устанавливаем фильтр
    compileFilterToHandler(arg->fil,handle);
//    стартуем снифер
    startSniff(handle);
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

int compileFilterToHandler(char *filter, pcap_t *handle) {
    int retl, retc, rets;
    retl=pcap_lookupnet(devName,&net,&mask,errbuf);
    if (retl==-1) {
        fprintf(stderr,"Can't lookupnet for device. Exiting.\n");
        exit(17);
    }
    retc=pcap_compile(handle,&fp,filter,0,net);
    if (retc==-1) {
        fprintf(stderr,"Can't compile filter. Exiting.\n");
        exit(16);
    }

    rets=pcap_setfilter(handle,&fp);
    if (rets==-1) {
        fprintf(stderr,"Can't set filter. Exiting.\n");
        exit(18);
    }

    return 1;
}

int startSniff(pcap_t* handle) {
    int r = pcap_loop(handle,0,callback_sniff,NULL);
    return r;
}
