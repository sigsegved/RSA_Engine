#ifndef __BASE64_H
#define __BASE64_H

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>

int DEBUG;

int get_base64_index (unsigned char ch ) ;
void print_octect(unsigned char *input,int len,int cols) ; 
int base64_encode (unsigned char *input, int ilen, unsigned char **output) ;
int base64_decode ( unsigned char *input,int ilen,unsigned char **output) ;


#endif
