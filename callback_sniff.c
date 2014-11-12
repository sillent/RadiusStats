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
            break;
        case AUTH_RES:
            rad_auth_res++;
            break;
        case AUTH_REJ:
            rad_auth_rej++;
            break;
        case ACCT_REQ:
            rad_acct_req++;
            sleep(10);
            break;
        case ACCT_RES:
            rad_acct_res++;
            break;
        default:
            break;
    }
    printf("auth_req: %lld acct_req: %lld\n",rad_auth_req, rad_acct_req);
}
