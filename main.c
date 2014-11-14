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
    
    // send to background
    pid_t pid;
    pid=fork();
    if (pid<0) {
        exit(EXIT_FAILURE);
    }
    if (pid>0) {
        exit(EXIT_SUCCESS);
    }
    
    pthread_t threadCounter;
    int t=pthread_create(&threadCounter,NULL,&sniffInit,(void *)&argStruct);
 
    // create LISTENER
    listener();

    
    
    return (EXIT_SUCCESS);
}

