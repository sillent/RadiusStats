/* 
 * File:   main.c
 * Author: santa
 *
 * Created on 7 ноября 2014 г., 15:01
 */


#include "sniffer.h"

/*
 * 
 */
int main(int argc, char** argv) {
    if (argc <= 1) {
        fprintf(stderr,"Usage %s <devName>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    sniffInit(argv[1], "port 1812 or port 1813");
    return (EXIT_SUCCESS);
}

