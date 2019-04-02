#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "callback_sniff.h"

static unsigned long long auth_req;
static unsigned long long auth_res;
static unsigned long long auth_rej;
static unsigned long long acct_req;
static unsigned long long acct_res;

static int sockfd;

struct mesg_t {
    char mes[3];
    long long arg;
};

int listener();
void grepp(struct mesg_t, struct sockaddr_in );
int sendmsgto(struct sockaddr_in, unsigned long long);

int listener() {
    sockfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if (sockfd == -1) {
        fprintf(stderr,"Cannot create socket on listener()\n");
        exit(EXIT_FAILURE);
    }
    struct mesg_t *msg=malloc(sizeof(struct mesg_t));
    memset(msg,0,sizeof(struct mesg_t));
    struct sockaddr_in serv_addr, client_addr;
//    memset(&serv_addr,0,sizeof(serv_addr));
    memset(&client_addr,0,sizeof(client_addr));
    serv_addr.sin_family=AF_INET;
    serv_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    serv_addr.sin_port=htons(SERVER_PORT);

    int rb=bind(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr));
    if (rb<0) {
        fprintf(stderr,"Cannot bind socket on listener()\n");
        exit(EXIT_FAILURE);
    }

    socklen_t sendsize=sizeof(client_addr);
    while (1) {
        int recl=recvfrom(sockfd,msg,sizeof(struct mesg_t),0,(struct sockaddr *)&client_addr,&sendsize);
        if (recl >= 0) {
            grepp(*msg,client_addr);
        }
    }
    return 1;
}
void grepp(struct mesg_t data,struct sockaddr_in respondto) {
    struct mesg_t d=data;
    if (strcmp(d.mes,"auq")==0) {
        auth_req=be64toh(d.arg);
    }
    if (strcmp(d.mes,"aur")==0) {
        auth_res=be64toh(d.arg);
    }
    if (strcmp(d.mes,"auj")==0) {
        auth_rej=be64toh(d.arg);
    }
    if (strcmp(d.mes,"acq")==0) {
        acct_req=be64toh(d.arg);
    }
    if (strcmp(d.mes,"acr")==0) {
        acct_res=be64toh(d.arg);
    }
    // req to get statistics data
    if (strcmp(d.mes,"guq")==0) {
        sendmsgto(respondto,auth_req);
    }
    if (strcmp(d.mes,"gus")==0) {
        sendmsgto(respondto,auth_res);
    }
    if (strcmp(d.mes,"guj")==0) {
        sendmsgto(respondto,auth_rej);
    }
    if (strcmp(d.mes,"gcq")==0) {
        sendmsgto(respondto,acct_req);
    }
    if (strcmp(d.mes,"gcs")==0) {
        sendmsgto(respondto,acct_res);
    }
}
int sendmsgto(struct sockaddr_in to, unsigned long long data) {
    long long t=htobe64(data);
    int rs=sendto(sockfd,&t,sizeof(t),0,(struct sockaddr *)&to,sizeof(to));
//    printf("send socket: %d\n",rs);
    return rs;
}
