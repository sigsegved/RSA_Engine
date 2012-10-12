
#ifndef __X509_H
#define __X509_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmp.h>
#include <fcntl.h>
#include "rsa.h"
#include "pem_der.h"
#include "base64.h"

int get_public_key(unsigned char *x509_der,public_key **pu) ;
unsigned char * get_der_x509(char *cert_file) ;


#endif