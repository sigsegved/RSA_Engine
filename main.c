#include "pem_der.h"
#include "rsa.h"
#include "base64.h"
#include "x509.h"
#include <unistd.h>

#define ENCRYPT 1
#define DECRYPT 2
#define SIGN 3
#define VERIFY 4

void usage();

int main(int argc, char *argv[])
{
	/* code */
	private_key *pvt_key;
	public_key *pub_key;
	private_key_mpz *pvt_key_mpz;
	public_key_mpz *pub_key_mpz;
	unsigned char * c_pvt_key;
	unsigned char * c_pub_key;
	unsigned char *c_pub_decoded,*signature;
	unsigned char *c_pvt_decoded,*signed_msg,*buff;
	int key_len_pu = 0;
	int key_len_pv = 0,slen,bytes_read;
	char *keytype;
	char *infile;
	char *outfile,*keyfile;
	int is_valid = 1,operation;
	char c,mlen,is_sign_valid;
	int get_public_key_from_certificate=0;
	FILE *fp;
	/*
		GENRSA OPTIONS 
		e/d -> ENCRYPT/DECRYPT
		k -> KEY TO use; VALUE : public/private
		f -> KEY FILE
		i -> input file ; VALUE : filepath
		o -> output file; VALUE : filepath

	*/



	

	while (is_valid && (c = getopt (argc, argv, "cedsvVk:i:o:")) != -1) {
		switch (c) {
			case 'e':
				operation = ENCRYPT;
				break;
			case 'd':
				operation = DECRYPT;
				break;
			case 's':
				operation = SIGN;
				break;
			case 'v':
				operation = VERIFY;
				break;
			case 'k':
				keyfile = optarg;
				break;
			case 'c':
				get_public_key_from_certificate = 1;
				break;
			case 'i':
				infile = optarg;
				break;
			case 'o': 
				outfile = optarg;
				break;
			case 'V': 
				DEBUG = 1;
				break;
			default:
				usage();
				is_valid = 0;
				break;
		}
	}

	pvt_key_mpz = (private_key_mpz *)malloc(sizeof(private_key_mpz));
	pub_key_mpz = (public_key_mpz *)malloc(sizeof(public_key_mpz));
	pvt_key = (private_key *)malloc(sizeof(private_key));
	pub_key = (public_key *)malloc(sizeof(public_key));


	switch (operation) {
		case ENCRYPT:
			//READ PUBLIC KEY
			if(get_public_key_from_certificate) {
				uchar * x509 = get_der_x509(keyfile);
				get_public_key(x509,&pub_key);
				c_pub_key = encode_public_key(pub_key,&key_len_pu);
				
			} else {
				fp = open_file(keyfile,1);
				c_pub_key = read_key(fp,&key_len_pu);
				fclose(fp);
			}
			key_len_pu = base64_decode(c_pub_key,key_len_pu,&c_pub_decoded);
			pub_key = parse_pub_key(c_pub_decoded,key_len_pu);
			byte_key_to_mpz_key(NULL,pub_key,NULL,pub_key_mpz);
			rsa_encrypt_file(infile,outfile,pub_key_mpz);
			break;
		case DECRYPT:
			fp = open_file(keyfile,1);
			c_pvt_key = read_key(fp,&key_len_pv);
			key_len_pv = base64_decode(c_pvt_key,key_len_pv,&c_pvt_decoded);
			pvt_key = parse_pvt_key(c_pvt_decoded,key_len_pv);
			fclose(fp);
			byte_key_to_mpz_key(pvt_key,NULL,pvt_key_mpz,NULL);
			rsa_decrypt_file(infile,outfile,pvt_key_mpz);
			break;
		case SIGN:
			fp = open_file(keyfile,1);
			c_pvt_key = read_key(fp,&key_len_pv);
			key_len_pv = base64_decode(c_pvt_key,key_len_pv,&c_pvt_decoded);
			pvt_key = parse_pvt_key(c_pvt_decoded,key_len_pv);
			fclose(fp);
			byte_key_to_mpz_key(pvt_key,NULL,pvt_key_mpz,NULL);

			fp = open_file(infile,1);
			if(!fp) {
				perror("INPUT FILE ERROR : ");
				return -1;
			}
			buff = (uchar *)malloc(117);
			bytes_read = fread(buff,1,117,fp); 
			if(bytes_read < 0) {
				perror("READ ERROR : ");
				return -1;
			}
			fclose(fp);
			signed_msg = rsa_sign(buff,bytes_read,pvt_key_mpz,&slen);
			fp = open_file(outfile,2);
			fwrite(signed_msg,1,slen,fp);
			free(signed_msg);
			fclose(fp);
			break;
		case VERIFY:
			fp = open_file(keyfile,1);
			c_pub_key = read_key(fp,&key_len_pu);
			key_len_pu = base64_decode(c_pub_key,key_len_pu,&c_pub_decoded);
			pub_key = parse_pub_key(c_pub_decoded,key_len_pu);
			fclose(fp);
			byte_key_to_mpz_key(NULL,pub_key,NULL,pub_key_mpz);
			//outfile is output so read 117
			
			fp = open_file(outfile,1);
			if(!fp) {
				perror("INPUT FILE ERROR : ");
				return -1;
			}
			buff = (uchar *)malloc(117);
			mlen = fread(buff,1,117,fp); 
			if(bytes_read < 0) {
				perror("READ ERROR : ");
				return -1;
			}
			fclose(fp);
			//infile is signature so read 128 bytes
			fp = open_file(infile,1);
			if(!fp) {
				perror("INPUT FILE ERROR : ");
				return -1;
			}
			signature = (uchar *)malloc(128);
			slen = fread(signature,1,128,fp); 
			if(bytes_read < 0) {
				perror("READ ERROR : ");
				return -1;
			}
			fclose(fp);
			is_sign_valid = rsa_verify(buff,mlen,signature,slen,pub_key_mpz);
			if(is_sign_valid)
				printf("Verified OK\n");
			else
				printf("Verification Failure\n");
			break;
		default :
			usage();
			break;

	}

	free(pvt_key_mpz);
	free(pub_key_mpz);
	free(pub_key);
	free(pvt_key);
	return 0;
}

void usage() {
	printf("RSA -[e/d/s/v] -k [keyfile] -i [input_file] -o [output_file]\n");
	printf("Example -- \n Encrypt  \n\t RSA -e -k public.pem -i input -o output\n Decrypt \n\t RSA -d -k private.pem -i input -o output\n Sign \n\t RSA -s -k private.pem -i input -o signfile\n Verify \n\t RSA -v -k public.pem -i signfile -o output\n");
	exit(-1);
}
