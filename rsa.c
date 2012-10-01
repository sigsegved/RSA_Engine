#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmp.h>


#define KEY_SIZE_BITS 1024
#define KEY_SIZE_BYTES (KEY_SIZE_BITS/8)
int main () {

	char rand_str[KEY_SIZE_BYTES];
	int i;
	mpz_t rand_int,p,q,m,n,e;

	mpz_set_ui(e,17);

	mpz_init(rand_int);

	srand(time(NULL));

	for (i=0;i<KEY_SIZE_BYTES;i++) {
		rand_str[i] = rand() % 0xFF;
	}

	mpz_import(rand_int, KEY_SIZE_BYTES,1, sizeof(rand_str[0]),0,0,rand_str);

	//printf("rand_str : %s\n",mpz_get_str(NULL,16,rand_int));
	

	while(!mpz_cmp_ui(pmode,1)) {
		mpz_nextprime(p,tmp1);
		mpz_mod(pmode,p,e);
	}

	memset(rand_str,0,KEY_SIZE_BYTES);

	for (i=0;i<KEY_SIZE_BYTES;i++) {
		rand_str[i] = rand() % 0xFF;
	}

	mpz_import(rand_int, KEY_SIZE_BYTES,1, sizeof(rand_str[0]),0,0,rand_str);

	//printf("rand_str : %s\n",mpz_get_str(NULL,16,rand_int));

	mpz_nextprime(q,tmp1);

	n = mpz_mul(p,q);

	mpz_sub_ui(p1,p,1);
	mpz_sub_ui(q1,q,1);

	m = mpz_mul(p1,q1);


}
