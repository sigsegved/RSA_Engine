#include "pem_der.h"


int get_data_len(unsigned char *pkey, int *index) {

	int data_len=0;
	int i,len_octet_count;

	if (pkey[(*index)++]&0x2) {
		//seperator 
		if(pkey[(*index)] >= 128){

			len_octet_count = pkey[(*index)]^0x80;

			for(i=0;i<len_octet_count;i++) {

				data_len = data_len | pkey[++(*index)];
			}
			(*index)++;
			
		}else {
			//use one byte for data length
			data_len = pkey[(*index)];
			(*index)++;

		}
	}
	return data_len;
			
}

private_key * parse_pvt_key(unsigned char *pkey, int plen) { 

	int index = 7;
	int data_len = 0;
	int data_end = 0;
	int sep_counter = 0;
	void *data;

	private_key *pvt_key;

	pvt_key = (private_key *)malloc(sizeof(private_key));
	memset(pvt_key,0,sizeof(private_key));

	while (index < plen) { 
		//at this point index should point to the start of the data;
		data_len  = get_data_len(pkey,&index);
		if(data_len == 0)
			continue;
		data_end = data_len + index;
		data = malloc(data_len);
		if(pkey[index] == '\0'){
			data_len--;
			memcpy(data,(pkey+index+1),data_len);
			index = index+data_len+1;
		}else {
			memcpy(data,(pkey+index),data_len);
			index = index+data_len;
		}
		/*for ( ;index<data_end;index++) {
			//copy data;
			printf("%2x ",pkey[index]);
				
		}*/
#if 1
		switch(sep_counter) {
			case 0:
				pvt_key->mod = (unsigned char *)malloc(data_len);
				memset(pvt_key->mod,0,data_len);
				pvt_key->mod_len = data_len;
				memcpy(pvt_key->mod,data,data_len);
				if(DEBUG)
					printf("modulus[%d]:\n",data_len);
				break;
			case 1:
				pvt_key->pub_exp = (unsigned char *)malloc(data_len);
				memset(pvt_key->pub_exp,0,data_len);
				pvt_key->pub_exp_len = data_len;
				memcpy(pvt_key->pub_exp,data,data_len);
				if(DEBUG)
					printf("PublicExponent[%d]:\n",data_len);
				break;
			case 2:
				pvt_key->pvt_exp = (unsigned char *)malloc(data_len);
				memset(pvt_key->pvt_exp,0,data_len);
				pvt_key->pvt_exp_len = data_len;
				memcpy(pvt_key->pvt_exp,data,data_len);
				if(DEBUG)
					printf("PrivateExponent[%d]:\n",data_len);
				break;
			case 3:
				pvt_key->prime1 = (unsigned char *)malloc(data_len);
				memset(pvt_key->prime1,0,data_len);
				pvt_key->prime1_len = data_len;
				memcpy(pvt_key->prime1,data,data_len);
				if(DEBUG)
					printf("prime1[%d]:\n",data_len);
				break;
			case 4:
				pvt_key->prime2 = (unsigned char *)malloc(data_len);
				memset(pvt_key->prime2,0,data_len);
				pvt_key->prime2_len = data_len;
				memcpy(pvt_key->prime2,data,data_len);
				if(DEBUG)
					printf("prime2[%d]:\n",data_len);
				break;
			case 5:
				pvt_key->exp1 = (unsigned char *)malloc(data_len);
				memset(pvt_key->exp1,0,data_len);
				pvt_key->exp1_len = data_len;
				memcpy(pvt_key->exp1,data,data_len);
				if(DEBUG)
					printf("exponent1[%d]:\n",data_len);
				break;
			case 6:
				pvt_key->exp2 = (unsigned char *)malloc(data_len);
				memset(pvt_key->exp2,0,data_len);
				pvt_key->exp2_len = data_len;
				memcpy(pvt_key->exp2,data,data_len);
				if(DEBUG)
					printf("exponent2[%d]:\n",data_len);
				break;
			case 7:
				pvt_key->coeff = (unsigned char *)malloc(data_len);
				memset(pvt_key->coeff,0,data_len);
				pvt_key->coeff_len = data_len;
				memcpy(pvt_key->coeff,data,data_len);
				if(DEBUG)
					printf("coefficient[%d]:\n",data_len);
				break;
			default:
				break;
		}
		if(DEBUG)
			print_octect(data,data_len,15);
		free(data);
		sep_counter++;
#endif
	}
	return pvt_key;


}

public_key * parse_pub_key(unsigned char *pkey, int plen) { 
	int index = 25;
	int data_len = 0;
	int data_end = 0;
	int sep_counter = 0;
	public_key *pub_key;
	void *data;
	pub_key = (public_key *)malloc(sizeof(public_key));
	memset(pub_key,0,sizeof(public_key));

	while (index < plen) { 

		data_len = get_data_len(pkey,&index);
		if(data_len <=0)
			continue;
		data_end = data_len+index;
		data = malloc(data_len);
		memset(data,0,data_len);
		if(pkey[index] == '\0'){
			data_len--;
			memcpy(data,(pkey+index+1),data_len);
			index = index+data_len+1;
		}else {
			memcpy(data,(pkey+index),data_len);
			index = index+data_len;
		}
		if(sep_counter == 0) {
			pub_key->mod = (unsigned char *)malloc(data_len);
			pub_key->mod_len = data_len;
			memset(pub_key->mod,0,data_len);
			memcpy(pub_key->mod,data,data_len);
			if(DEBUG)
				printf("modulus[%d] : \n",data_len);

		}else if(sep_counter == 1) {
			pub_key->pub_exp = (unsigned char *)malloc(data_len);
			pub_key->pub_exp_len = data_len;
			memset(pub_key->pub_exp,0,data_len);
			memcpy(pub_key->pub_exp,data,data_len);
			if(DEBUG)
				printf("PublicExponent[%d] : \n",data_len);
		}else {
			printf("UNEXPECTED STUFF IN PUBLIC KEY\n");
		}
		sep_counter++;
		if(DEBUG)
			print_octect(data,data_len,15);
		free(data);

	}
	return pub_key;
	
}
unsigned char * encode_size(unsigned char *comp,int size,int *len,int *null_set) {
	unsigned char *encoded_size;
	int esize = 0;
	if(comp && comp[0]&0x80)  {
		*null_set = 1;
		size++;
	}else
		*null_set = 0;
	if(size>127)
		esize = 3;
	else
		esize = 2;
	encoded_size = (unsigned char*)malloc(esize);
	encoded_size[0] = 0x2;
	if(size > 127) {
		encoded_size[1] = 0x81;
		encoded_size[2] = size;
	}else {
		encoded_size[1] = size;
	}

	*len = esize;


	return encoded_size;
}



unsigned char *encode_private_key(private_key *pvt_key, int *rlen) {
	unsigned char *pem_pvt_key;
	int b64_pvt_key_len;
	int index=0;
	unsigned char *b64_encoded_pvt_key;
	unsigned char *size_encode_str;
	int pvt_key_size = pvt_key->mod_len+pvt_key->pub_exp_len+pvt_key->pvt_exp_len+pvt_key->prime1_len+pvt_key->prime2_len+pvt_key->exp1_len+pvt_key->exp2_len+pvt_key->coeff_len+25;
	int len = 0;
	int null_set = 0;
	
	pem_pvt_key = (unsigned char *)malloc(pvt_key_size);
	memset(pem_pvt_key,0,pvt_key_size);
	
	pem_pvt_key[index++] = 0x30;


	index += 3;

	pem_pvt_key[index++] = 0x2;
	pem_pvt_key[index++] = 0x1;
	pem_pvt_key[index++] = 0x0;


	size_encode_str = encode_size(pvt_key->mod,pvt_key->mod_len,&len,&null_set);
	strncpy((pem_pvt_key+index),size_encode_str,len);
	index += len;
	if(null_set)
		pem_pvt_key[index++]=0x0;
	memcpy((pem_pvt_key+index),pvt_key->mod,pvt_key->mod_len);
	index+=pvt_key->mod_len;

	size_encode_str = encode_size(pvt_key->pub_exp,pvt_key->pub_exp_len,&len,&null_set);
	strncpy((pem_pvt_key+index),size_encode_str,len);
	index += len;
	if(null_set)
		pem_pvt_key[index++]=0x0;
	memcpy((pem_pvt_key+index),pvt_key->pub_exp,pvt_key->pub_exp_len);
	index+=pvt_key->pub_exp_len;

	size_encode_str = encode_size(pvt_key->pvt_exp,pvt_key->pvt_exp_len,&len,&null_set);
	strncpy((pem_pvt_key+index),size_encode_str,len);
	index += len;
	if(null_set)
		pem_pvt_key[index++]=0x0;
	memcpy((pem_pvt_key+index),pvt_key->pvt_exp,pvt_key->pvt_exp_len);
	index+=pvt_key->pvt_exp_len;

	size_encode_str = encode_size(pvt_key->prime1,pvt_key->prime1_len,&len,&null_set);
	strncpy((pem_pvt_key+index),size_encode_str,len);
	index += len;
	if(null_set)
		pem_pvt_key[index++]=0x0;
	memcpy((pem_pvt_key+index),pvt_key->prime1,pvt_key->prime1_len);
	index+=pvt_key->prime1_len;

	size_encode_str = encode_size(pvt_key->prime2,pvt_key->prime2_len,&len,&null_set);
	strncpy((pem_pvt_key+index),size_encode_str,len);
	index += len;
	if(null_set)
		pem_pvt_key[index++]=0x0;
	memcpy((pem_pvt_key+index),pvt_key->prime2,pvt_key->prime2_len);
	index+=pvt_key->prime2_len;

	size_encode_str = encode_size(pvt_key->exp1,pvt_key->exp1_len,&len,&null_set);
	strncpy((pem_pvt_key+index),size_encode_str,len);
	index += len;
	if(null_set)
		pem_pvt_key[index++]=0x0;
	memcpy((pem_pvt_key+index),pvt_key->exp1,pvt_key->exp1_len);
	index+=pvt_key->exp1_len;

	size_encode_str = encode_size(pvt_key->exp2,pvt_key->exp2_len,&len,&null_set);
	strncpy((pem_pvt_key+index),size_encode_str,len);
	index += len;
	if(null_set)
		pem_pvt_key[index++]=0x0;
	memcpy((pem_pvt_key+index),pvt_key->exp2,pvt_key->exp2_len);
	index+=pvt_key->exp2_len;

	size_encode_str = encode_size(pvt_key->coeff,pvt_key->coeff_len,&len,&null_set);
	strncpy((pem_pvt_key+index),size_encode_str,len);
	index += len;
	if(null_set)
		pem_pvt_key[index++]=0x0;
	memcpy((pem_pvt_key+index),pvt_key->coeff,pvt_key->coeff_len);
	index+=pvt_key->coeff_len;


	size_encode_str = encode_size(NULL,index,&len,&null_set);
	pem_pvt_key[1] = 0x82;
	pem_pvt_key[2] = (index-4)>>8;
	pem_pvt_key[3] = (index-4)&0x00FF;
	
	if(DEBUG)
		print_octect(pem_pvt_key,index,22);

	pvt_key_size = index;

	b64_pvt_key_len = base64_encode(pem_pvt_key,pvt_key_size,&b64_encoded_pvt_key);
	int i=0;

	while(i<b64_pvt_key_len) {
		for(;i<i+65&&i<b64_pvt_key_len;i++)
			printf("%c",b64_encoded_pvt_key[i]);
		i = i+65;
		printf("\n");
	}

	*rlen = b64_pvt_key_len;

	return b64_encoded_pvt_key;
	
}


unsigned char * encode_public_key(public_key *pub_key,int *rlen) {

	unsigned char *pem_pub_key;
	unsigned char *b64_encoded_pub_key;
	unsigned char *size_encode_str;
	int b64_pub_key_len;
	int index=0;
	int len = 0;
	int null_set = 0;
	int pub_key_size = pub_key->mod_len+pub_key->pub_exp_len+35;
	pem_pub_key = (unsigned char *)malloc(pub_key_size);
	memset(pem_pub_key,0,pub_key_size);

	pem_pub_key[index] = 0x30;
	index = 25;

	size_encode_str = encode_size(pub_key->mod,pub_key->mod_len,&len,&null_set);
	strncpy((pem_pub_key+index),size_encode_str,len);
	index += len;
	if(null_set)
		pem_pub_key[index++]=0x0;
	memcpy((pem_pub_key+index),pub_key->mod,pub_key->mod_len);
	index+=pub_key->mod_len;

	size_encode_str = encode_size(pub_key->pub_exp,pub_key->pub_exp_len,&len,&null_set);
	strncpy((pem_pub_key+index),size_encode_str,len);
	index += len;
	if(null_set)
		pem_pub_key[index++]=0x0;
	memcpy((pem_pub_key+index),pub_key->pub_exp,pub_key->pub_exp_len);
	index+=pub_key->pub_exp_len;


	pem_pub_key[1] = 0x81;
	pem_pub_key[2] = (index-3)&0x00FF;
	pem_pub_key[3] = 0x30;
	pem_pub_key[4] = 0xd;
	unsigned char printable_pkey_str[17] = {0x6,0x9,0x2a,0x86,0x48,0x86,0xf7,0xd,0x1,0x1,0x1,0x5,0x0,0x3,0x81,0x8d,0x0};
	memcpy((pem_pub_key+5),printable_pkey_str,17);

	pem_pub_key[22] = 0x30;
	pem_pub_key[23] = 0x81;
	pem_pub_key[24] = (index-25);
	
	print_octect(pem_pub_key,index,22);

	pub_key_size = index;

	b64_pub_key_len = base64_encode(pem_pub_key,pub_key_size,&b64_encoded_pub_key);
	int i=0;

	while(i<b64_pub_key_len) {
		for(;i<i+65&&i<b64_pub_key_len;i++)
			printf("%c",b64_encoded_pub_key[i]);
		i = i+65;
		printf("\n");
	}

	*rlen = b64_pub_key_len;

	return b64_encoded_pub_key;
	
}

FILE * open_file(char * file_name, int mode) {
	FILE *fp;
	if(!file_name)
		return NULL;
	
	if(mode == READ_ONLY)
		fp = fopen(file_name,"r");
	else 
		fp = fopen(file_name,"w+");


	if(!fp) 
		perror("FILE ERROR : ");
	
	return fp;
	
}


unsigned char * read_key(FILE *fp,int *len) {
	unsigned char *buffer;
	unsigned char line[512];
	int size=0,index=0;
	if(!fp)
		return NULL;
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	buffer = (unsigned char *)malloc(size);
	memset(buffer,0,size);

	while(!feof(fp)) {
		memset(line,0,512);
		fgets(line,512,fp);
		if((line[0] == '-') || (line[0] == '\0'))
			continue;
		strncpy(buffer+index,line,strlen(line)-1);
		index = index+strlen(line)-1;
	}
	(*len) = index;
	return buffer;
}

int write_key(FILE *fp, unsigned char *buff, int bufflen,int keytype) {

	unsigned char line[66];
	int index = 0, len = 0;

	if(!fp)
		return 0;

	if(keytype == PRIVATE)
		fputs("-----BEGIN RSA PRIVATE KEY-----\n",fp);
	else 
		fputs("-----BEGIN PUBLIC KEY-----\n",fp);
			
	
	while (index<bufflen) {
		memset(line,0,66);
		len = 64;
		if(bufflen-index < 64)
			len = bufflen-index;
		strncpy(line,buff+index,len);
		line[len] = '\n';
		fputs(line,fp);
		index = index + len;
	}

	if(keytype == PRIVATE)
		fputs("-----END RSA PRIVATE KEY-----\n",fp);
	else
		fputs("-----END PUBLIC KEY-----\n",fp);


	return index-64;

}
