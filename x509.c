#include "x509.h"



unsigned char * get_der_x509(char *cert_file) {
	FILE *fp;
	uchar *x509_cert,*x509_cert_decoded,*x509_hash;
	int cert_len,x509_cert_decoded_len;

	fp = open_file(cert_file,1);
	x509_cert = read_key(fp,&cert_len);
	x509_cert_decoded_len = base64_decode(x509_cert,cert_len,&x509_cert_decoded);

	if(DEBUG){
		printf("x509_certificate\n");
		print_octect(x509_cert_decoded,x509_cert_decoded_len,22);
	}
	return x509_cert_decoded;
}

int get_public_key(unsigned char *x509_der,public_key **pu) {
	int counter;
	int index = 0,i,size; 
	int seq_size,seq_size_len;
	int elems =0, seq_count = 0;

	(*pu) = (public_key *)malloc(sizeof(public_key));

	while(seq_count < 2) {
		if(x509_der[index++] == 0x30) {
			seq_size_len = x509_der[index++] & 0x3F;
			index += seq_size_len;
			seq_count++;
		}
	}

	//the second  sequence contains the 6 elems 
	while(elems!=5) {
		switch(x509_der[index++]){
			case 0x02:		//INTEGER
			case 0x30:		//SEQUENCE
				if(x509_der[index]<0x80){
					seq_size = x509_der[index++];

				} else{
					seq_size_len = x509_der[index++] & 0x3F;
					for (i=0;i<seq_size_len;i++){
						size = x509_der[index++];
						seq_size |= size << (8*(seq_size_len-(i+1)));
					}
				}
				elems++;
				index+=seq_size;
				seq_size = 0;
				seq_size_len = 0;
		}
	}

	//Now index point to the sequence of sequence which contains the public key... 
	//contains two integers mod and exp
	if(x509_der[index++] == 0x30) {
			seq_size_len = x509_der[index++] & 0x3F;
			index += seq_size_len;
	}

	if(x509_der[index++] == 0x30) {
		seq_size = 0;
		if(x509_der[index]<0x80){
			seq_size = x509_der[index++];
		} else {
			seq_size_len = x509_der[index++] & 0x3F;
			for (i=0;i<seq_size_len;i++){
				size = x509_der[index++];
				seq_size |= size << (8*(seq_size_len-(i+1)));
			}
		}
	}
	index+=seq_size;
	if(x509_der[index++] == 0x3) {
			seq_size_len = x509_der[index++] & 0x3F;
			index += seq_size_len;
	}
	if(x509_der[index]==0x0)
		index++;
	if(x509_der[index++]==0x30) {
			seq_size_len = x509_der[index++] & 0x3F;
			index += seq_size_len;
	}
	if(x509_der[index++] == 0x02) {
		//MOD 
		seq_size_len = 0;
		seq_size = 0;
		if(x509_der[index]<0x80){
			seq_size = x509_der[index];
		} else{
			seq_size_len = x509_der[index++] & 0x3F;
			for (i=0;i<seq_size_len;i++){
				size = x509_der[index++];
				seq_size |= size << (8*(seq_size_len-(i+1)));
			}
		}
		if(x509_der[index]==0x0){
			index++;
			seq_size--;
		}
		(*pu)->mod_len = seq_size;
		(*pu)->mod = (unsigned char *)malloc((*pu)->mod_len);
		memset((*pu)->mod,0,(*pu)->mod_len);
		memcpy((*pu)->mod,x509_der+index,(*pu)->mod_len);
		index+=seq_size;
	}
	if(x509_der[index++] == 0x02) {
		//EXP 
		seq_size_len = 0;
		seq_size = 0;
		if(x509_der[index]<0x80){
			seq_size = x509_der[index++];
		} else{
			seq_size_len = x509_der[index++] & 0x3F;
			for (i=0;i<seq_size_len;i++){
				size = x509_der[index++];
				seq_size |= size << (8*(seq_size_len-(i+1)));
			}
		}
		(*pu)->pub_exp_len = seq_size;
		(*pu)->pub_exp = (unsigned char *)malloc((*pu)->pub_exp_len);
		memset((*pu)->pub_exp,0,(*pu)->pub_exp_len);
		memcpy((*pu)->pub_exp,x509_der+index,(*pu)->pub_exp_len);
		index+=seq_size;
	}

	return 1;

}