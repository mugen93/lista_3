#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <conio.h>



/**
 * Encrypt or decrypt, depending on flag 'should_encrypt'
 */
void en_de_crypt(int should_encrypt, FILE *ifp, FILE *ofp, unsigned char *ckey, unsigned char *ivec) {
	//printf("\nkrypce\n");
    const unsigned BUFSIZE=1024;
    unsigned char *read_buf =(unsigned char*)malloc(BUFSIZE);
    unsigned char *cipher_buf;
    unsigned blocksize;
    int out_len;
    EVP_CIPHER_CTX ctx;

    EVP_CipherInit(&ctx, EVP_aes_128_cbc(), ckey, ivec, should_encrypt);
    blocksize = EVP_CIPHER_CTX_block_size(&ctx);
    cipher_buf = (unsigned char*)malloc(BUFSIZE + blocksize);


    while (1) {

        // Read in data in blocks until EOF. Update the ciphering with each read.

        int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
        EVP_CipherUpdate(&ctx, cipher_buf, &out_len, read_buf, numRead);
        fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
        if (numRead < BUFSIZE) { // EOF
            break;
        }
    }

    // Now cipher the final block and write it out.

    EVP_CipherFinal(&ctx, cipher_buf, &out_len);
    fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

    // Free memory

    free(cipher_buf);
    free(read_buf);
}

int main(void) 
{

	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	X509           *cert, *cacert;
	STACK_OF(X509) *cacertstack=NULL;
	PKCS12         *pkcs12bundle;
	EVP_PKEY       *cert_privkey;
	FILE           *cacertfile, *certfile, *keyfile, *pkcs12file;
	//unsigned char *passphrase=(unsigned char *)malloc(sizeof(char)*16);
	std::string passphrase="";
	unsigned char next=NULL;
	int            bytes = 0;
	RSA *rsakey;
	printf("\nPodaj has³o do keystore'a\n");
	int length=0;
	while (1)
	{
		next=getch();
		if (next==13)
			break;
		//printf("-: %c - %d\n",next,(int)next);
		passphrase+=next;
		length++;
	}
	

	if (!(pkcs12file = fopen("keystore.p12", "rb"))) 
	{
        fprintf(stderr, "Error opening file %s\n", "keystore.p12");
		system("pause");
		exit(1);
    }
	pkcs12bundle = d2i_PKCS12_fp(pkcs12file, NULL);
    fclose (pkcs12file);
    if (!pkcs12bundle) 
	{
        fprintf(stderr, "Error reading PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
		system("pause");
		exit(1);
    }
	
	 if (!PKCS12_parse(pkcs12bundle, passphrase.c_str(), &cert_privkey, &cert, &cacertstack)) 
	 {
        fprintf(stderr, "Error parsing PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
		system("pause");
        exit (1);
    }

	
	PKCS12_free(pkcs12bundle);
	
	int pkeyLen;
	unsigned char *ucBuf=NULL, *uctempBuf;
	char *iv1=(char*)malloc(SHA256_DIGEST_LENGTH*2+1);
	pkeyLen = i2d_PUBKEY(cert_privkey, NULL);
	//printf("%d",pkeyLen);
	ucBuf = (unsigned char *)malloc(pkeyLen+1);
	uctempBuf = ucBuf;
	//printf("\ <- tuten klucz len siema\n %d",sizeof(cert_privkey));
	i2d_PUBKEY(cert_privkey, &uctempBuf);
	
	 
	//system("pause");




	unsigned char hash[SHA256_DIGEST_LENGTH];
    	SHA256_CTX sha256;
    	SHA256_Init(&sha256);
    	SHA256_Update(&sha256, uctempBuf, pkeyLen);
    	SHA256_Final(hash, &sha256);
	for(int i=0;i<SHA256_DIGEST_LENGTH;i++)
	{
		sprintf(iv1+(i*2), "%02x", hash[i]);
	}



	unsigned char *ckey = (unsigned char*)ucBuf;
	std::string ivec="";
	////unsigned char *ivec=(unsigned char*)malloc(16*sizeof(const char));
	for (int q=0;q<16;q++)
		ivec+=iv1[q];
	const char *abc=ivec.c_str();
	//for (int q=0;q<256;q++)
	//	printf("%d-: %c\n",q,abc[q]);
	//char *IV=(char*)malloc(16);
	//strcpy(IV,ivec.c_str());
    FILE *fIN, *fOUT;

    // First encrypt the file

    fIN = fopen("ewok.mp3", "rb"); 
    fOUT = fopen("cypherewok.mp3", "wb"); 
	//fIN=fopen("1.txt","rb");
	//fOUT=fopen("2.txt","wb");

	//system("pause");
    en_de_crypt(true, fIN, fOUT, ckey, (unsigned char*)abc);

    fclose(fIN);
    fclose(fOUT);

    //Decrypt file now

	/*

    fIN = fopen("cypherewok.mp3", "rb"); 
    fOUT = fopen("decryptedewok.mp3", "wb");
	//fIN=fopen("2.txt","rb");
	//fOUT=fopen("3.txt","wb");

    en_de_crypt(false, fIN, fOUT, ckey, (unsigned char*)abc);

	*/

    fclose(fIN);
    fclose(fOUT);


	


    return 0;
} 