#include "rsa.h"
#include "pem_der.h"


void fill_buffer(char *rand_str,int size) {
	int i =0;

	//memset(rand_str,0,BLOCK_SIZE);
	memset(rand_str,0,size);
	for (i=0;i<size;i++) {
		rand_str[i] = (rand() % 0xFF) + 1;
	}

	rand_str[0] |= 0xC0;
	rand_str[size-1] |= 0x01;
}


void key_generation (private_key_mpz *pvt_key, public_key_mpz *pub_key) {

	mpz_t rand_int,p,p1,q,q1,m,n,d,e,exp1,exp_2,coeff;
	int i;
	mpz_t pmode,qmode;
	unsigned char rand_str[BLOCK_SIZE];
	mpz_init(p);
	mpz_init(p1);
	mpz_init(q);
	mpz_init(q1);
	mpz_init(m);
	mpz_init(n);
	mpz_init(d);
	mpz_init(e);
	mpz_init(exp1);
	mpz_init(exp_2);
	mpz_init(pmode);
	mpz_init(qmode);
	mpz_init(rand_int);
	mpz_init(coeff);

	//set e
	mpz_set_ui(e,E);
	srand(time(NULL));
	fill_buffer(rand_str,BLOCK_SIZE/2);
	mpz_import(rand_int, BLOCK_SIZE/2,1, sizeof(rand_str[0]),0,0,rand_str);
	//find p such that p mode !=1
	mpz_nextprime(p,rand_int);
	do{
		mpz_nextprime(p,p);
		mpz_mod(pmode,p,e);
	}while(!mpz_cmp_ui(pmode,1));

	//find q such that q mod e != 1
	fill_buffer(rand_str,BLOCK_SIZE/2);
	mpz_import(rand_int, BLOCK_SIZE/2,1, sizeof(rand_str[0]),0,0,rand_str);
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

	mpz_invert(coeff, q, p);
	if (mpz_sgn(coeff) == -1) { 
		mpz_add(coeff, coeff,p);
	}


	mpz_mod(exp1,d,p1);
	mpz_mod(exp_2,d,q1);
	mpz_init(pvt_key->mod);
	mpz_init_set(pvt_key->mod,n);
	mpz_init_set(pvt_key->pub_exp,e);
	mpz_init_set(pvt_key->pvt_exp,d);
	mpz_init_set(pvt_key->prime1,p);
	mpz_init_set(pvt_key->prime2,q);
	mpz_init_set(pvt_key->exp1,exp1);
	mpz_init_set(pvt_key->exp2,exp_2);
	mpz_init_set(pvt_key->coeff,coeff);

	mpz_init_set(pub_key->mod,n);
	mpz_init_set(pub_key->pub_exp,e);

#if 1
        mpz_gcd(rand_int, e, m);
        printf("gcd(e, m) = [%s]\n", mpz_get_str(NULL, 10, rand_int));

	printf("p [%d]: %s\n",(int)mpz_sizeinbase(p,2),mpz_get_str(NULL,10,p));
	printf("q [%d]: %s\n",(int)mpz_sizeinbase(q,2),mpz_get_str(NULL,16,q));
	printf("m [%d]: %s\n",(int)mpz_sizeinbase(m,2),mpz_get_str(NULL,16,m));
	printf("n [%d]: %s\n",(int)mpz_sizeinbase(n,2),mpz_get_str(NULL,16,n));
	printf("d [%d]: %s\n",(int)mpz_sizeinbase(d,2),mpz_get_str(NULL,16,d));
#endif

}

size_t convert_mpz_to_byte (mpz_t rop, unsigned char **rop_bytes) {
	size_t size = 0;
	(*rop_bytes)= mpz_export(NULL,&size,1,1,0,0,rop);
	return size;
}
void convert_byte_to_mpz (mpz_t *rop, unsigned char *rop_bytes,int len) {
	mpz_import((*rop),len,1,1,0,0,rop_bytes);
}
void byte_key_to_mpz_key(private_key *pkey, public_key *pukey,private_key_mpz *pkey_mpz, public_key_mpz *pukey_mpz) {
	if(pkey && pkey_mpz) {
		mpz_init(pkey_mpz->mod);
		mpz_init(pkey_mpz->pub_exp);
		mpz_init(pkey_mpz->pvt_exp);
		mpz_init(pkey_mpz->prime1);
		mpz_init(pkey_mpz->prime2);
		mpz_init(pkey_mpz->exp1);
		mpz_init(pkey_mpz->exp2);
		mpz_init(pkey_mpz->coeff);
		convert_byte_to_mpz(&(pkey_mpz->mod),pkey->mod,pkey->mod_len);
		convert_byte_to_mpz(&(pkey_mpz->pub_exp),pkey->pub_exp,pkey->pub_exp_len);
		convert_byte_to_mpz(&(pkey_mpz->pvt_exp),pkey->pvt_exp,pkey->pvt_exp_len);
		convert_byte_to_mpz(&(pkey_mpz->prime1),pkey->prime1,pkey->prime1_len);
		convert_byte_to_mpz(&(pkey_mpz->prime2),pkey->prime2,pkey->prime2_len);
		convert_byte_to_mpz(&(pkey_mpz->exp1),pkey->exp1,pkey->exp1_len);
		convert_byte_to_mpz(&(pkey_mpz->exp2),pkey->exp2,pkey->exp2_len);
		convert_byte_to_mpz(&(pkey_mpz->coeff),pkey->coeff,pkey->coeff_len);
	}
	if(pukey && pukey_mpz) {
		mpz_init(pukey_mpz->mod);
		mpz_init(pukey_mpz->pub_exp);
		convert_byte_to_mpz(&(pukey_mpz->mod),pukey->mod,pukey->mod_len);
		convert_byte_to_mpz(&(pukey_mpz->pub_exp),pukey->pub_exp,pukey->pub_exp_len);

	}
}
void mpz_key_to_byte_key(private_key_mpz *pkey_mpz, public_key_mpz *pukey_mpz, private_key *pkey, public_key *pukey) {

	 pkey->mod_len = convert_mpz_to_byte(pkey_mpz->mod,&pkey->mod);
	 pkey->pub_exp_len = convert_mpz_to_byte(pkey_mpz->pub_exp,&pkey->pub_exp);
	 pkey->pvt_exp_len = convert_mpz_to_byte(pkey_mpz->pvt_exp,&pkey->pvt_exp);
	 pkey->prime1_len = convert_mpz_to_byte(pkey_mpz->prime1,&pkey->prime1);
	 pkey->prime2_len = convert_mpz_to_byte(pkey_mpz->prime2,&pkey->prime2);
	 pkey->exp1_len = convert_mpz_to_byte(pkey_mpz->exp1,&pkey->exp1);
	 pkey->exp2_len = convert_mpz_to_byte(pkey_mpz->exp2,&pkey->exp2);
	 pkey->coeff_len = convert_mpz_to_byte(pkey_mpz->coeff,&pkey->coeff);
	 pukey->mod_len = convert_mpz_to_byte(pukey_mpz->mod,&pukey->mod);
	 pukey->pub_exp_len = convert_mpz_to_byte(pukey_mpz->pub_exp,&pukey->pub_exp);
}

unsigned char * EME_PKCS1_V1_5_DECODE(uchar *EM,int emlen,int *m_len) {
	int ps_len=0;
	int i=0;

	if(emlen < 10 && EM[0]!=0x2) {
		printf("EME-PKCS1-V1_5-DECODE ERROR\n");
		return NULL;
	}

	while(EM[i] != 0x0) 
		i++;

	if(++i < 7 ){
		printf("EME-PKCS1-V1_5-DECODE ERROR\n");
		return NULL;
	}

	*m_len = emlen - i ;

	return (EM+i);
	
}


unsigned char * EME_PKCS1_V1_5_ENCODE(uchar *M,int mlen,int *c_len) {
	uchar *ps;
	uchar *em;
	int ps_len=0;
	if(mlen > *c_len-10) {
		printf("EME-PKCS1-V1_5-ENCODE ERROR\n");
		return NULL;
	}
	ps_len = *c_len-mlen-3;
	ps = (uchar *)malloc(ps_len);
	memset(ps,0,ps_len);
	fill_buffer(ps,ps_len);
	em = (uchar *)malloc((*c_len));
	em[0] = 0x0;
	em[1] = 0x2;
	memcpy((em+2),ps,ps_len);
	em[ps_len+1] = 0x0;
	memcpy((em+2+ps_len),M,mlen);


	if(mlen+ps_len+3 != *c_len)
		printf("MISMATCH OF EMLEN TO C_LEN\n");


	free(ps);

	return em;

}
int RSA_POWM(mpz_t m,mpz_t e,mpz_t n, mpz_t *c) {

	int diff = mpz_cmp (m,e);
	if (diff>=0) {
		printf("MSG REP 'm' is out of range\n");
		return 0;
	}
	mpz_powm((*c),m,n,e);
	return 1;
}

unsigned char * block_encrypt(unsigned char *M,int mlen,int *c_len,public_key_mpz *pu) {
	int k = mpz_sizeinbase(pu->mod,2)/8;
	int x = k;
	size_t size = 0;
	mpz_t m;mpz_init(m);
	mpz_t c;mpz_init(c);mpz_init(c);
	uchar *EM;
	uchar *C;
	EM = EME_PKCS1_V1_5_ENCODE(M,mlen,&x);
	mpz_import(m,128,1,1,0,0,EM);
	free(EM);
	if(RSA_POWM(m,pu->mod,pu->pub_exp,&c) == 0) 
		return NULL;
	C = mpz_export(NULL,&size,1,1,0,0,c);
	*c_len = (int)size;
	return C;
}


unsigned char * block_decrypt(unsigned char *C,int clen,int *mlen, private_key_mpz *pv) {
	size_t size = 0;
	mpz_t m;mpz_init(m);
	mpz_t c;mpz_init(c);
	uchar *EM;
	uchar *M,*M_tmp;
	int k = mpz_sizeinbase(pv->mod,2)/8;
	if(clen != k) {
		printf("DECRYPTION ERROR\n");
		return NULL;
	}
	mpz_import(c,128,1,1,0,0,C);
	if(RSA_POWM(c,pv->mod,pv->pvt_exp,&m) == 0 ) 
		return NULL;
	EM = mpz_export(NULL,&size,1,1,0,0,m);
	EM[size]=0x0;
	if(DEBUG)
		print_octect(EM,128,22);
	M_tmp = EME_PKCS1_V1_5_DECODE(EM,k-1,mlen);
	M = (uchar *)malloc(*mlen);
	memset(M,0,*mlen);
	memcpy(M,M_tmp,*mlen);
	free(EM);
	return M;
}

void rsa_encrypt(unsigned char *M,int mlen,unsigned char **C,int *c_len,public_key_mpz *pu) {

	int k = mpz_sizeinbase(pu->mod,2)/8;
	int em_len = 0;
	if( mlen%k > 0 )
		*c_len = (mlen/k+1)*k;
	else 
		*c_len = mlen;

	(*C) = (uchar *)malloc(*c_len);

	uchar *em = block_encrypt(M,mlen,&em_len,pu);

	memcpy((*C),em,em_len);
	free(em);
}

void rsa_decrypt(unsigned char *C,int c_len,unsigned char **M,int *m_len,private_key_mpz *pv) {
	int dm_len = 0	;
	uchar *dm = block_decrypt(C,c_len,&dm_len,pv);
	(*M) = dm;
	*m_len = dm_len;
}


int rsa_decrypt_file(char *infile,char *outfile,private_key_mpz *pv) {
	FILE *ifp,*ofp;
	int k = mpz_sizeinbase(pv->mod,2)/8;
	uchar *C,M[128],bytes_written,total_bytes_written=0;
	int clen,mlen;

	ifp = open_file(infile,1);
	ofp = open_file(outfile,2);

	if((!ifp)||(!ofp)){
		printf("FILE OPEN ERROR\n");
		
	}
	memset(M,0,128);
	while((mlen = fread(M,1,128,ifp))==128){
		C = block_decrypt(M,mlen,&clen,pv);
		if((bytes_written=fwrite(C,1,clen,ofp))<0){
			perror("WRITE ERROR");
			break;
		}
		free(C);
		total_bytes_written += bytes_written;
		memset(M,0,128);
	}
	fclose(ifp);
	fclose(ofp);
	return total_bytes_written;
}

int rsa_encrypt_file(char *infile,char *outfile,public_key_mpz *pu) {
	FILE *ifp,*ofp;
	int k = mpz_sizeinbase(pu->mod,2)/8;
	uchar *C,M[117],bytes_written,total_bytes_written=0;
	int clen,mlen;

	ifp = open_file(infile,1);
	ofp = open_file(outfile,2);

	if((!ifp)||(!ofp)){
		printf("FILE OPEN ERROR\n");
		
	}

	memset(M,0,117);
	while((mlen = fread(M,1,117,ifp))>0){
		C = block_encrypt(M,mlen,&clen,pu);
		C[clen]=0;
		if((bytes_written=fwrite(C,1,clen,ofp))<0){
			perror("WRITE ERROR");
			break;
		}
		free(C);
		total_bytes_written += bytes_written;
		memset(M,0,117);
	}
	fclose(ifp);
	fclose(ofp);
	return total_bytes_written;
}

unsigned char * EMSA_PKCS1_v1_5_ENCODE(unsigned char *M, int m_len, int emlen) {
	unsigned char hash[20];
	unsigned char *EM;
	int index = 0;
	unsigned char DigestInfo[] = {0x30,0x21,0x30,0x9,0x6,0x5,0x2b,0xe,0x3,0x2,0x1a,0x5,0x0,0x4,0x14};
	unsigned char *T,*PS;
	T = (unsigned char *)malloc(36);

	//computer hash
	SHA1(M, m_len, hash);
	memset(T,0,36);
	memcpy(T,DigestInfo,15);
	memcpy(T+15,hash,20);
	PS = (uchar *) malloc(emlen-35-3);
	memset(PS,0xff,emlen-35-3);

	EM = (unsigned char *) malloc(emlen);
	memset(EM,0,emlen);

	EM[index++] = 0x0;
	EM[index++] = 0x1;
	memcpy((EM+index),PS,emlen-35-3);
	index+= (emlen-35-3);
	EM[index++] = 0x0;
	memcpy((EM+index),T,35);
	return EM;

}

unsigned char * rsa_sign(unsigned char *M,int mlen,private_key_mpz *pv,int *slen) {

	int k = mpz_sizeinbase(pv->mod,2)/8;
	int emlen = k;
	size_t size = 0;
	mpz_t m;mpz_init(m);
	mpz_t c;mpz_init(c);
	uchar *EM;
	uchar *C;
	EM = EMSA_PKCS1_v1_5_ENCODE(M,mlen,emlen);
	mpz_import(m,emlen,1,1,0,0,EM);
	free(EM);
	if(RSA_POWM(m,pv->mod,pv->pvt_exp,&c) == 0) 
		return NULL;
	C = mpz_export(NULL,&size,1,1,0,0,c);
	*slen = size;
	return C;
}

int rsa_verify(unsigned char *M,int mlen,unsigned char *S,int slen,public_key_mpz *pu) {

	int k = mpz_sizeinbase(pu->mod,2)/8;
	size_t size = 0;
	int emlen = k;
	uchar *EM,*EM1;
	uchar *C;

	mpz_t m;mpz_init(m);
	mpz_t s;mpz_init(s);
	mpz_t c;mpz_init(c);
	
	if(slen!=k){
		printf("Signed msg length error \n");
		return 0;
	}
	mpz_import(s,slen,1,1,0,0,S);
	if(RSA_POWM(s,pu->mod,pu->pub_exp,&c) == 0) 
		return 0;
	EM = mpz_export(NULL,&size,1,1,0,0,c);

	EM1 = EMSA_PKCS1_v1_5_ENCODE(M,mlen,emlen);

	if(size==emlen-1 && (memcmp(EM,EM1+1,size) == 0))
		return 1;
	else 
		return 0;
}



