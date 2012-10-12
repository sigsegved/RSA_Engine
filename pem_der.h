#ifndef __PEM_DER_H
#define __PEM_DER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "base64.h"

#define READ_ONLY 1
#define READ_WRITE 2
#define PRIVATE 12121
#define PUBLIC 12122



typedef struct _private_key {
	unsigned char *mod;
	int mod_len;
	unsigned char *pub_exp;
	int pub_exp_len;
	unsigned char *pvt_exp;
	int pvt_exp_len;
	unsigned char *prime1;
	int prime1_len;
	unsigned char *prime2;
	int prime2_len;
	unsigned char *exp1;
	int exp1_len;
	unsigned char *exp2;
	int exp2_len;
	unsigned char *coeff;
	int coeff_len;

}private_key ;

typedef struct _public_key {
	unsigned char *mod;
	int mod_len;
	unsigned char *pub_exp;
	int pub_exp_len;
}public_key;

int get_data_len(unsigned char *pkey, int *index);
private_key * parse_pvt_key(unsigned char *pkey, int plen) ; 
public_key * parse_pub_key(unsigned char *pkey, int plen) ;
unsigned char *encode_private_key(private_key *,int *);
unsigned char *encode_public_key(public_key *,int *);
int write_key(FILE *fp, unsigned char *buff, int bufflen,int);
unsigned char * read_key(FILE *fp,int *);
FILE * open_file(char * file_name, int mode);

#endif
