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



/*

wczytaj klucz2 z toConfig.p12 
otwieramy/tworzymy config.txt <- klucz2
	pobieramy œcie¿kê do keystore.p12
	pobieramy passphrase do keystore.p12
	pytanie o PIN
		podany - pobieramy PIN i porównujemy,
		niepodany - wpisujemy podany.
otwieramy keystore.p12
	pobieramy klucz1
otwieramy zaszyfrowany plik <- klucz1
	puszczamy muzê z bufora
	czyœcimy bufory.

*/

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

void openConfig(FILE *ifp, unsigned char *ckey, unsigned char *ivec, std::string PIN,std::string PASS,std::string PATH) 
{
	//printf("\nkrypce\n");
    const unsigned BUFSIZE=1024;
    unsigned char *read_buf =(unsigned char*)malloc(BUFSIZE);
    unsigned char *cipher_buf;
    unsigned blocksize;
    int out_len;
    EVP_CIPHER_CTX ctx;
	bool flag=true;

    EVP_CipherInit(&ctx, EVP_aes_128_cbc(), ckey, ivec, 0);
    blocksize = EVP_CIPHER_CTX_block_size(&ctx);
    cipher_buf = (unsigned char*)malloc(BUFSIZE + blocksize);

	//std::string rPIN="", rPASS="", rPATH="";
    while (flag) 
	{

        // Read in data in blocks until EOF. Update the ciphering with each read.

        int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
		if (numRead < BUFSIZE) 
		{ // EOF
			EVP_CipherFinal(&ctx, cipher_buf, &out_len);
            flag=false;
        }
		else
			EVP_CipherUpdate(&ctx, cipher_buf, &out_len, read_buf, numRead);
        //fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
		//bool flag=false;
	}
		int q;
		for (int d=0;d<out_len;d++)
			printf("%c",cipher_buf[d]);
		for (q=0;q<out_len-8;q++)
		{
			if (cipher_buf[q]=='P'&&cipher_buf[q+1]=='I'&&cipher_buf[q+2]=='N'&&cipher_buf[q+3]==':'&&cipher_buf[q+4]==' ')
			{
				PIN+=cipher_buf[q+5];
				PIN+=cipher_buf[q+6];
				PIN+=cipher_buf[q+7];
				PIN+=cipher_buf[q+8];
				q+=9;
			}
			else if (cipher_buf[q]=='P'&&cipher_buf[q+1]=='A'&&cipher_buf[q+2]=='S'&&cipher_buf[q+3]=='S'&&cipher_buf[q+4]==':')
			{
				int p;
				for (p=q+5;p<out_len;p++)
				{
					if(cipher_buf[p]==13)
						break;
					PASS+=cipher_buf[p];
				}
				q=p+1;
			}
			else if (cipher_buf[q]=='P'&&cipher_buf[q+1]=='A'&&cipher_buf[q+2]=='T'&&cipher_buf[q+3]=='H'&&cipher_buf[q+4]==':')
			{
				int p;
				for (p=q+5;p<out_len;p++)
				{
					if(cipher_buf[p]==13)
						break;
					PATH+=cipher_buf[p];
				}
				q=p+1;
			}
		}

        
    
	
	/*char* read*///PIN=(char*)malloc(sizeof(char)*(rPIN.length()+1));
	/*char* read*///PASS=(char*)malloc(sizeof(char)*(1+rPASS.length()));
	/*char* read*///PATH=(char*)malloc(sizeof(char)*(1+rPATH.length()));
	/*
	for (int q=0;q<rPIN.length();q++)
		PIN[q]=rPIN[q];*/
	//PIN[rPIN.length()+1]='\n';
	PIN+='\n';
	/*for (int q=0;q<rPASS.length();q++)
		PASS[q]=rPASS[q];*/
	//PASS[rPASS.length()+1]='\n';
	PASS+='\n';
	/*for (int q=0;q<rPATH.length();q++)
		PATH[q]=rPATH[q];*/
	//PATH[rPATH.length()+1]='\n';
	PATH+='\n';

    // Now cipher the final block and write it out.

    
    //fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

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
	FILE			*toConfigFile, *config, *encrypted;
	PKCS12 *toConfigBundle;
	EVP_PKEY *toConfigKey;
	//unsigned char *passphrase=(unsigned char *)malloc(sizeof(char)*16);
	std::string passphrase="";
	unsigned char next=NULL;
	int            bytes = 0;
	RSA *rsakey;


	if (!(toConfigFile = fopen("toConfig.p12", "rb"))) 
	{
        fprintf(stderr, "Error opening file %s\n", "toConfig.p12");
		system("pause");
		exit(1);
    }
	toConfigBundle = d2i_PKCS12_fp(toConfigFile, NULL);
    fclose (toConfigFile);
    if (!toConfigBundle) 
	{
        fprintf(stderr, "Error reading PKCS#12 toConfig file\n");
        ERR_print_errors_fp(stderr);
		system("pause");
		exit(1);
    }
	
	 if (!PKCS12_parse(toConfigBundle, "qwerty", &toConfigKey, &cert, &cacertstack)) 
	 {
        fprintf(stderr, "Error parsing PKCS#12 toConfig file\n");
        ERR_print_errors_fp(stderr);
		system("pause");
        exit (1);
    }

	
	PKCS12_free(toConfigBundle);


	int conLen;
	unsigned char *ucBuffer=NULL,*uctempBuf2;
	char *iv2=(char*)malloc(SHA256_DIGEST_LENGTH*2+1);
	conLen = i2d_PUBKEY(toConfigKey, NULL);
	//printf("%d",pkeyLen);
	ucBuffer = (unsigned char *)malloc(conLen+1);
	//uctempBuf2 =(char*)malloc(SHA256_DIGEST_LENGTH*2+1);
	uctempBuf2=ucBuffer;
	//printf("\ <- tuten klucz len siema\n %d",sizeof(cert_privkey));
	i2d_PUBKEY(toConfigKey, &uctempBuf2);

	unsigned char hash1[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha2561;
	SHA256_Init(&sha2561);
	SHA256_Update(&sha2561, ucBuffer, conLen);
	SHA256_Final(hash1, &sha2561);
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(iv2 + (i * 2), "%02x", hash1[i]);
    }


	std::string iv="";
		//unsigned char *ivec=(unsigned char*)malloc(16*sizeof(const char));
	printf("IV-:");
	for (int q=0;q<16;q++)
	{
		iv+=iv2[q];
		printf("%c", iv2[q]);
	}
	printf("\n");
	const char *aa=iv.c_str();

	std::string inPIN="";
	std::string readPIN="", readPATH="", readPASS="";
	//char *r1=NULL,*r3=NULL,*r2=NULL;
	//unsigned char *IV=(unsigned char*)readPIN.c_str();

	if(config=fopen("config.txt", "rb"))
	{
		printf("Podaj PIN");
		for (int q=0;q<4;q++)
		{
			char n=getch();
			inPIN+=n;
		}
		//FILE *deConf;

		
		//char c;
		openConfig(config,ucBuffer,(unsigned char*) aa,readPIN,readPASS,readPATH);
			
		/*for(int q=0;q>=0;q++)
		{
			if (r1[q]==13)
				break;
			readPIN+=r1[q];
		}
		for(int q=0;q>=0;q++)
		{
			if (r2[q]==13)
				break;
			readPASS+=r2[q];
		}
		for(int q=0;q>=0;q++)
		{
			if (r1[q]==13)
				break;
			readPATH+=r3[q];
		}*/
		//printf("%s, %s, %s\n",readPIN,readPASS,readPATH);
		if (!std::strcmp(inPIN.c_str(),readPIN.c_str()))
		{
			printf("Niepoprawny PIN\n");
			exit(1);
		}

	}
	else //create config.txt
	{
	
		printf("\nPodaj PIN (4 znaki)");
		for (int q=0;q<4;q++)
		{
			char n=getch();
			inPIN+=n;
		}
		std::string inPASS="";
		printf("\nPodaj passphrase do Keystore'a");
		while(true)
		{
			char n=getch();
			if (n==13)
				break;
			inPASS+=n;
		}
		std::string inPATH="";
		printf("\nPodaj sciezke dostepu do Keystore'a");
		while(true)
		{
			char n;
			scanf("%c",&n);
			if (n=='\n')
				break;
			inPATH+=n;
		}
		config=fopen("toConfig.txt", "wb");
		//std::string=
		fwrite("PIN: ", sizeof(unsigned char), 5, config);
		fwrite(inPIN.c_str(), sizeof(unsigned char), inPIN.length(), config);
		fwrite("\n", sizeof(unsigned char), 1, config);
		fwrite("PASS:", sizeof(unsigned char), 5, config);
		fwrite(inPASS.c_str(), sizeof(unsigned char), inPASS.length(), config);
		fwrite("\n", sizeof(unsigned char), 1, config);
		fwrite("PATH:", sizeof(unsigned char), 5, config);
		fwrite(inPATH.c_str(), sizeof(unsigned char), inPATH.length(), config);
		fclose(config);

		config=fopen("toConfig.txt","rb");
		FILE *config2=fopen("config.txt","wb");
		en_de_crypt(true,config,config2,ucBuffer,(unsigned char*) aa);
		fclose(config);
		fclose(config2);
		//remove("toConfig.txt");
		printf("Instalacja zakonczona sukcesem (mam nadzieje)\n");
		system("pause");
		return 0;
	}













	/*printf("\nPodaj has³o do keystore'a\n");
	int length=0;
	while (1)
	{
		next=getch();
		if (next==13)
			break;
		//printf("-: %c - %d\n",next,(int)next);
		passphrase+=next;
		length++;
	}*/
	

	if (!(pkcs12file = fopen(readPATH.c_str(), "rb"))) 
	{
        fprintf(stderr, "Error opening file %s\n", readPATH);
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
	
	 if (!PKCS12_parse(pkcs12bundle, readPASS.c_str(), &cert_privkey, &cert, &cacertstack)) 
	 {
        fprintf(stderr, "Error parsing PKCS#12 file\n");
        ERR_print_errors_fp(stderr);
		system("pause");
        exit (1);
    }

	
	PKCS12_free(pkcs12bundle);
	
	int pkeyLen;
	unsigned char *ucBuf=NULL,*uctempBuf ;
	char*iv1=(char*)malloc(SHA256_DIGEST_LENGTH*2+1);
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
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(iv1 + (i * 2), "%02x", hash[i]);
    }



	unsigned char *ckey = (unsigned char*)uctempBuf;
	std::string ivec="";
	//unsigned char *ivec=(unsigned char*)malloc(16*sizeof(const char));
	for (int q=0;q<16;q++)
		ivec+=iv1[q];
	const char *abc=ivec.c_str();
	//for (int q=0;q<256;q++)
	//	printf("%d-: %c\n",q,abc[q]);
	//char *IV=(char*)malloc(16);
	//strcpy(IV,ivec.c_str());
    FILE *fIN, *fOUT;

    // First encrypt the file

	/*

    fIN = fopen("ewok.mp3", "rb"); 
    fOUT = fopen("cypherewok.mp3", "wb"); 
	//fIN=fopen("1.txt","rb");
	//fOUT=fopen("2.txt","wb");

	//system("pause");
    en_de_crypt(true, fIN, fOUT, ckey, (unsigned char*)abc);

    fclose(fIN);
    fclose(fOUT);

	*/

    //Decrypt file now
	std::string readFILE="";
	printf("Podaj sciezke pliku\n");
	char sign=NULL;
	while (sign!=13)// sign!='\n'
	{
		scanf("%c",&sign);
		readFILE+=sign;
	}
	
	fIN = fopen(readFILE.c_str(),"wb");
    //fIN = fopen("cypherewok.mp3", "rb"); 
    fOUT = fopen("decrypted.mp3", "wb");
	//fIN=fopen("2.txt","rb");
	//fOUT=fopen("3.txt","wb");

    en_de_crypt(false, fIN, fOUT, ckey, (unsigned char*)abc);

	

    fclose(fIN);
    fclose(fOUT);


	


    return 0;
}