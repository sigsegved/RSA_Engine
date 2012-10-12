#include "base64.h"

const unsigned char base64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
int get_base64_index (unsigned char ch ) {

	if(ch>=48&&ch<=57)
		return (52+ch-48);
	else if(ch>=65&&ch<=90)
		return (ch-65);
	else if(ch>=97&&ch<=122)
		return (26+ch-97);
	else if(ch == '+')
		return 62;
	else if(ch == '/')
		return 63;
	else 
		return -1;


}

void print_octect(unsigned char *input,int len,int col) { 
	int i = 0;
	printf("\t");
	while(i<len) { 
		printf("%2x:",input[i]&0xff);
		i++;
		if(i%col == 0 )
			printf("\n\t");
	}
	printf("\n");

}




int base64_encode (unsigned char *input, int ilen, unsigned char **output) {
	
	int index = 0;
	int octet[3]={0}; 
	int x = (ilen/3)+1;
	int pad;
	int sum  = 0;
	int outputlen = ceil(4*(ilen+pad)/3)+1;
	int oindex = 0;

	if(ilen%3 == 0)
		pad = 0;
	else 
		pad = 3*x - ilen;

	(*output) = (unsigned char *) malloc(outputlen);
	memset((*output),0,outputlen);

	while (index<ilen) { 
		octet[0] = input[index++]<<16;
		if(index<=ilen){
			octet[1] = input[index++]<<8;
		}
		if(index<=ilen) {
			octet[2] = input[index++];
		}
		sum = octet[0]+octet[1]+octet[2];
		octet[0] = 0;
		octet[1] = 0;
		octet[2] = 0;
		//printf("%c",base64chars[(sum&0xFC0000)>>18]);
		(*output)[oindex++] = base64chars[(sum&0xFC0000)>>18];
		//printf("%c",base64chars[(sum&0x3F000)>>12]);
		(*output)[oindex++] = base64chars[(sum&0x3F000)>>12];
		if(index>=ilen && pad > 1){
			(*output)[oindex++] = '=';
			//printf("=");
		}
		else{
			(*output)[oindex++] = base64chars[(sum&0xFC0)>>6];
			//printf("%c",base64chars[(sum&0XFC0)>>6]);
		}
		if(index>=ilen && pad > 0){
			(*output)[oindex++] = '=';
			//printf("=");
		}
		else  {
			(*output)[oindex++] = base64chars[(sum&0x3F)];
			//printf("%c",base64chars[(sum&0x3F)]);
		}
			
		sum = 0;

	}
	//printf("\n");
	return oindex;

}


int base64_decode ( unsigned char *input,int ilen,unsigned char **output) {

	int index = 0;
	int octet[3]={0}; 
	int pad = 0 ;
	int sum  = 0;
	int b64_index = 0 ;
	int oindex = 0;

	(*output) = (unsigned char *)malloc(ilen);

	memset((*output),0,ilen);
	
	while (index<ilen) { 
		b64_index = get_base64_index(input[index++]);
		sum = sum | b64_index << 18;
		b64_index = get_base64_index(input[index++]);
		sum = sum | b64_index << 12;
		if ( index <= ilen) {
			if( input[index] != '=') {
				b64_index = get_base64_index(input[index++]);
				sum = sum | b64_index << 6;
			}else {
				pad++;
				index++;
			}
		}			
		if ( index <= ilen ) {
			if(input[index] != '=') {
				b64_index = get_base64_index(input[index++]);
				sum = sum | b64_index;
			}else {
				pad++;
				index++;
			}
		}

		//printf("%c",(sum&0xFF0000)>>16);
		(*output)[oindex++] = (sum&0xFF0000)>>16;
		if(pad<2){
			//printf("%c",(sum&0xFF00)>>8);
			(*output)[oindex++] = (sum&0xFF00)>>8;
		}
		if(pad<1){
			//printf("%c",sum&0xFF);
			(*output)[oindex++] = (sum&0xFF);
		}
		sum = 0;
	}
	//printf("\n");
	return oindex;
}

