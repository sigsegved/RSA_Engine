#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmp.h>

#define E 17
#define KEY_SIZE_BITS 1024
#define BLOCK_SIZE 128


mpz_t rand_int,p,p1,q,q1,m,n,d,e;

char *rsa_encrypt(char *buff) {
	char *ebuff;
	mpz_t M,C;
	mpz_init(M);
	mpz_init(C);
	mpz_import(M,128,1,1,0,0,buff);
	mpz_powm(C,M,e,n);
	mpz_export(ebuff,NULL,1,1,0,0,C);
	return ebuff;
}

char *rsa_decrypt(char *ebuff) {
	char *buff;
	mpz_t C,M;
	mpz_init(C);
	mpz_init(M);
	mpz_import(C,128,1,1,0,0,ebuff);
	mpz_powm(M,C,d,n);
	mpz_export(buff,NULL,1,1,0,0,M);
	return buff;
}


void fill_buffer(char *rand_str) {
	int i =0;
	memset(rand_str,0,BLOCK_SIZE);
	for (i=0;i<BLOCK_SIZE;i++) {
		rand_str[i] = rand() % 0xFF;
	}
}



key_generation () {

	char rand_str[BLOCK_SIZE];
	int i;
	mpz_t pmode,qmode;

	mpz_init(p);
	mpz_init(p1);
	mpz_init(q);
	mpz_init(q1);
	mpz_init(m);
	mpz_init(n);
	mpz_init(d);
	mpz_init(e);
	mpz_init(pmode);
	mpz_init(qmode);
	mpz_init(rand_int);

	//set e
	mpz_set_ui(e,E);
	srand(time(NULL));
	fill_buffer(rand_str);
	mpz_import(rand_int, BLOCK_SIZE,1, sizeof(rand_str[0]),0,0,rand_str);
	//find p such that p mode !=1
	mpz_nextprime(p,rand_int);
	do{
		mpz_nextprime(p,p);
		mpz_mod(pmode,p,e);
	}while(!mpz_cmp_ui(pmode,1));

	//find q such that q mod e != 1
	fill_buffer(rand_str);
	mpz_import(rand_int, BLOCK_SIZE,1, sizeof(rand_str[0]),0,0,rand_str);
	mpz_nextprime(q,rand_int);
	do{
		mpz_nextprime(q,q);
		mpz_mod(qmode,q,e);
	}while(!mpz_cmp_ui(qmode,1)) ;


	// n = p*q
	mpz_mul(n,p,q);
	// m = (p-1)*(q-1)
	mpz_sub_ui(p1,p,1);
	mpz_sub_ui(q1,q,1);
	mpz_mul(m,p1,q1);

	if(mpz_invert(d,e,m)==0) { 
		printf("multiplicative inverse failed\n");
	}


#if DEBUG
	printf("p : %s\n",mpz_get_str(NULL,10,p));
	printf("q : %s\n",mpz_get_str(NULL,16,q));
	printf("m : %s\n",mpz_get_str(NULL,16,m));
	printf("n : %s\n",mpz_get_str(NULL,16,n));
	printf("e : %s\n",mpz_get_str(NULL,10,e));
	printf("d : %s\n",mpz_get_str(NULL,16,d));
	printf("GCD \n");
#endif

}

int main() {
	printf("hello world\n");
}

