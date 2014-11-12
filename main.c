/* 
 * File:   main.c
 * Author: santa
 *
 * Created on 7 ноября 2014 г., 15:01
 */


#include "sniffer.h"
#include <pthread.h>

/*
 * 
 */
int main(int argc, char** argv) {
    if (argc <= 1) {
        fprintf(stderr,"Usage %s <devName>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    char *deviceName=argv[1];
    char *filter="port 1812 or port 1813";
    
    struct snif_arg_t argStruct;
    argStruct.dev=deviceName;
    argStruct.fil=filter;
    
    pthread_t threadCounter;
    int t=pthread_create(&threadCounter,NULL,&sniffInit,(void *)&argStruct);

    sleep(100);
    
    
    return (EXIT_SUCCESS);
}

