#ifndef __RSA_H
#define __RSA_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmp.h>
#include <fcntl.h>
#include "pem_der.h"

#define E 65537
#define KEY_SIZE_BITS 1024
#define BLOCK_SIZE 128

typedef unsigned char uchar;



typedef struct _private_key_mpz { 
	mpz_t mod;	//n
	mpz_t pvt_exp;	//d
	mpz_t pub_exp;	//e
	mpz_t prime1;	//p
	mpz_t prime2;	//q
	mpz_t exp1;	//dmodp-1
	mpz_t exp2;	//dmodq-1
	mpz_t coeff;	//multiplicate inverse of q
}private_key_mpz;

typedef struct _public_key_mpz {
	mpz_t mod;	//n
	mpz_t pub_exp; 	//e
}public_key_mpz;

void fill_buffer(char *rand_str,int) ;
void key_generation (private_key_mpz *pvt_key, public_key_mpz *pub_key) ;
size_t convert_mpz_to_byte (mpz_t rop, unsigned char **rop_bytes); 
void mpz_key_to_byte_key(private_key_mpz *pkey_mpz, public_key_mpz *pukey_mpz, private_key *pkey, public_key *pukey); 
unsigned char * block_encrypt(unsigned char *M,int mlen,int *c_len,public_key_mpz *pu) ;
unsigned char * block_decrypt(unsigned char *C,int c_len,int *m_len,private_key_mpz *pv) ;
void rsa_encrypt(unsigned char *D,int d_len,unsigned char **C,int *c_len,public_key_mpz *) ;
void rsa_decrypt(unsigned char *C,int c_len,unsigned char **M,int *m_len,private_key_mpz *) ;
void byte_key_to_mpz_key(private_key *pkey, public_key *pukey,private_key_mpz *pkey_mpz, public_key_mpz *pukey_mpz);
int rsa_encrypt_file(char *infile, char *outfile, public_key_mpz *pu);
int rsa_decrypt_file(char *infile, char *outfile, private_key_mpz *pv);
unsigned char * rsa_sign(unsigned char *M,int mlen,private_key_mpz *pv,int *slen);
int rsa_verify(unsigned char *M,int mlen,unsigned char *S,int slen,public_key_mpz *pu);
#endif

