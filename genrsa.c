#include "pem_der.h"
#include "rsa.h"
#include "base64.h"
#include <unistd.h>

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
	unsigned char *c_pub_decoded;
	unsigned char *c_pvt_decoded;
	int key_len_pu = 0;
	int key_len_pv = 0;
	char *keytype;
	char *infile;
	char *outfile;
	int is_valid = 1;
	char c;
	FILE *ifp,*ofp;

	/*
		GENRSA OPTIONS 
		k -> KEY TO GENERATE; VALUE : public/private
		i -> input file ; VALUE : filepath
		o -> output file; VALUE : filepath
		if k is public and -i is given, then the input file is assumed to be private file . 
		if k is private and -i is given, ignore input file and generate private alone .

	*/

	if(argc < 4) {
		usage();
	}

	while (is_valid && (c = getopt (argc, argv, "vk:i:o:")) != -1) {
		switch (c) {
			case 'k':
				keytype = optarg;
				break;
			case 'i':
				infile = optarg;
				break;
			case 'o': 
				outfile = optarg;
				break;
			case 'v': 
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

	if(strcmp(keytype,"public")==0){
		//read private key from infile 
		//generate public key 
		
		ifp = open_file(infile,1);
		if(!ifp) {
			perror("FILE ERROR : ");
			return -1;
		}

		c_pvt_key = read_key(ifp,&key_len_pv);
		key_len_pv = base64_decode(c_pvt_key,key_len_pv,&c_pvt_decoded);
		pvt_key = parse_pvt_key(c_pvt_decoded,key_len_pv);
		fclose(ifp);
		pub_key->mod = pvt_key->mod;
		pub_key->mod_len = pvt_key->mod_len;
		pub_key->pub_exp = pvt_key->pub_exp;
		pub_key->pub_exp_len = pvt_key->pub_exp_len;
		c_pub_key = encode_public_key(pub_key,&key_len_pu);
		ofp = open_file(outfile,2);
		write_key(ofp,c_pub_key,key_len_pu,PUBLIC);
		fclose(ofp);

	} else if(strcmp(keytype,"private")==0){
		//generate private key and write the same to outfile
		//ignore infile
		key_generation(pvt_key_mpz,pub_key_mpz);
		mpz_key_to_byte_key(pvt_key_mpz,pub_key_mpz,pvt_key,pub_key);
		c_pvt_key = encode_private_key(pvt_key,&key_len_pv);
		c_pub_key = encode_public_key(pub_key,&key_len_pu);
		ofp = open_file(outfile,2);
		write_key(ofp,c_pvt_key,key_len_pv,PRIVATE);
		fclose(ofp);

	}
	free(pvt_key_mpz);
	free(pub_key_mpz);
	free(pub_key);
	free(pvt_key);
	return 0;
}

void usage() {
	printf("GENRSA -k [private|public] -i [input_file] -o [output_file]\n");
	printf("Example -- \n Generate private key  \n\t GENRSA -k private -o private.pem\n Generate public key for a private key \n\t GENRSA  -k public -i private.pem -o public.pem\n");
	exit(-1);
}
