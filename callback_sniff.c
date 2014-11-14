#include "callback_sniff.h"
void callback_sniff(u_char *user, const struct pcap_pkthdr *pkthdr, 
        const u_char *bytes) {
 
    const struct sniff_radius *radius;
    
    radius=(struct sniff_radius *)(bytes+SIZE_ETH_IP_UDP);
    int t=radius->r_code;

    switch(t)
    {
        case AUTH_REQ:
            rad_auth_req++;
            sendToServer(AUTH_REQ,rad_auth_req);
            break;
        case AUTH_RES:
            rad_auth_res++;
            sendToServer(AUTH_RES,rad_auth_res);
            break;
        case AUTH_REJ:
            rad_auth_rej++;
            sendToServer(AUTH_REJ,rad_auth_rej);
            break;
        case ACCT_REQ:
            rad_acct_req++;
            sendToServer(ACCT_REQ,rad_acct_req);
            break;
        case ACCT_RES:
            rad_acct_res++;
            sendToServer(ACCT_RES,rad_acct_res);
            break;
        default:
            break;
    }
//    printf("auth_req: %lld acct_req: %lld\n",rad_auth_req, rad_acct_req);
}
// структура передаваеомго сообщения
struct msgr {
    char name[3];
    long long value;
};
void sendToServer(int type, unsigned long long count) {
    struct msgr msgSend;
    memset(&msgSend,0,sizeof(msgSend));
    switch (type) {
        case AUTH_REQ:
            strcpy(msgSend.name,"auq");
            msgSend.value=htobe64(count);
            break;
        case AUTH_RES:
            strcpy(msgSend.name,"aur");
            msgSend.value=htobe64(count);
            break;
        case AUTH_REJ:
            strcpy(msgSend.name,"auj");
            msgSend.value=htobe64(count);
            break;
        case ACCT_REQ:
            strcpy(msgSend.name,"acq");
            msgSend.value=htobe64(count);
            break;
        case ACCT_RES:
            strcpy(msgSend.name,"acr");
            msgSend.value=htobe64(count);
            break;
        default:
            break;     
    }
    struct sockaddr_in server;
    int sockfd=socket(AF_INET,SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd==-1) {
        fprintf(stderr, "Cannot create socket on SendToServer()\n");
        exit(EXIT_FAILURE);
    }
    memset(&server,0,sizeof(struct sockaddr));
    server.sin_family=AF_INET;
    server.sin_addr.s_addr=inet_addr("127.0.0.1");
    server.sin_port=htons(SERVER_PORT);
    
    int conRet=connect(sockfd,(struct sockaddr *)&server,sizeof(server));
    if (conRet==-1) {
        fprintf(stderr,"Cannot connect to socket on SendToServer\n");
        exit(EXIT_FAILURE);
    }
    
    // SEND MESSAGE to SOCKET
    int sendRet=sendto(sockfd,(void *)&msgSend,sizeof(msgSend),0,(struct sockaddr *)&server,sizeof(server));
    
    if (sendRet==-1) {
        fprintf(stderr,"Message to server %s not send\n",inet_ntoa(server.sin_addr));
        exit(EXIT_FAILURE);
    }
    if ((close(sockfd))==-1) {
        fprintf(stderr,"Cannot close socket\n");
    }
    
    
}
