#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <string.h>
#include <string>
unsigned char * readStringFromFile(char* filename,int *keylen)
{
	FILE* myKey = fopen(filename, "rb");
	fseek(myKey, 0L, SEEK_END);
	long key_length = ftell(myKey);
	unsigned char* userKey = (unsigned char*)malloc(sizeof(unsigned char) * key_length/2);
	fseek(myKey, 0L, SEEK_SET);
	for (int i = 0; i < key_length/2; i++)
	{
		int value;
		fscanf(myKey, "%02x", &value);
		userKey[i] = value;
	}
	fclose(myKey);
	(*keylen) = key_length;
	return userKey;
}
void encrypt_aes_cbc(char *filename,AES_KEY* aesKey, int keylength, unsigned char* iv,unsigned char **ciphertext,int *cipher_length)
{
	FILE* myIn = fopen(filename, "rb");
	fseek(myIn, 0L, SEEK_END);
	long input_length = ftell(myIn);
	int padding = AES_BLOCK_SIZE - input_length % AES_BLOCK_SIZE;
	unsigned char iv_aux[100];
	memcpy(iv_aux, iv, AES_BLOCK_SIZE);
	unsigned char *content = (unsigned char*)malloc(sizeof(unsigned char) * (input_length + padding));
	(*ciphertext) = (unsigned char*)malloc(sizeof(unsigned char) * (input_length + padding));
	fseek(myIn, 0L, SEEK_SET);
	fread(content, sizeof(unsigned char), input_length, myIn);
	for (int i = 0; i < padding; ++i)
	{
		content[input_length + i] = padding;
	}
	int blckNumber = (input_length + padding) / AES_BLOCK_SIZE;
	unsigned char inBlck[AES_BLOCK_SIZE];
	printf("STRING TO HEXA:\n");
	for (int i = 0; i < (input_length + padding); i++)
	{
		printf("%02x ", content[i]);
		if ((i + 1) % 16 == 0)
		{
			printf("\n");
		}
	}
	for (int i = 0; i < blckNumber; i++)
	{
		unsigned char outBlck[AES_BLOCK_SIZE];
		for (int j = 0; j < AES_BLOCK_SIZE; j++)
		{
			inBlck[j] = content[i * AES_BLOCK_SIZE + j] ^ iv[j];
		}
		AES_encrypt(inBlck, outBlck, aesKey);
		memcpy((*ciphertext+i*AES_BLOCK_SIZE), outBlck, AES_BLOCK_SIZE);
		memcpy(iv, outBlck, AES_BLOCK_SIZE);
	}
	(*cipher_length) = input_length+padding;
	memcpy(iv,iv_aux, AES_BLOCK_SIZE);
	fclose(myIn);
	free(content);
}
void decrypt_aes_cbc(unsigned char *ciphertext,int cipher_length,AES_KEY* aesKey,int keylength,unsigned char*iv,unsigned char **plaintext) {
	(*plaintext) = (unsigned char*)malloc(sizeof(unsigned char) * cipher_length);
	int blckNumber = cipher_length / AES_BLOCK_SIZE;
	unsigned char inBlck[AES_BLOCK_SIZE];
	unsigned char iv_aux[100];
	memcpy(iv_aux, iv, keylength / 2);
	for (int i = 0; i < blckNumber; i++)
	{
		for (int j = 0; j < AES_BLOCK_SIZE; j++)
		{
			inBlck[j] = ciphertext[i * AES_BLOCK_SIZE + j];
		}
		unsigned char outBlck[AES_BLOCK_SIZE];
		AES_decrypt(inBlck, outBlck, aesKey);
		for (int j = 0; j < AES_BLOCK_SIZE; j++)
		{
			outBlck[j] ^= iv[j];
		}
		memcpy(iv, inBlck, AES_BLOCK_SIZE);
		memcpy((*plaintext + i * AES_BLOCK_SIZE), outBlck,AES_BLOCK_SIZE);
		
	}
	memcpy(iv, iv_aux, AES_BLOCK_SIZE);
}
void encrypt_aes_ctr(unsigned char* plaintext, int text_length, AES_KEY* aesKey, int keylength, unsigned char* iv, unsigned char** ciphertext)
{
	unsigned char iv_aux[AES_BLOCK_SIZE];
	memcpy(iv_aux, iv, AES_BLOCK_SIZE);
	(*ciphertext) = (unsigned char*)malloc(sizeof(unsigned char) * text_length);
	unsigned char* nonce = (unsigned char*)malloc(sizeof(unsigned char) * AES_BLOCK_SIZE);
	int counter = 0;
	memset(nonce, 0, AES_BLOCK_SIZE);
	memcpy(nonce, iv, AES_BLOCK_SIZE);
	int blckNumber = text_length / AES_BLOCK_SIZE;
	int index = AES_BLOCK_SIZE - 1;
	for (int i = 0; i < blckNumber; i++)
	{
		unsigned char outBlck[AES_BLOCK_SIZE];
		AES_encrypt(nonce, outBlck, aesKey);
		for (int j = 0; j < AES_BLOCK_SIZE; j++)
		{
			outBlck[j] ^= plaintext[i * AES_BLOCK_SIZE + j];
		}
		memcpy((*ciphertext + i * AES_BLOCK_SIZE), outBlck, AES_BLOCK_SIZE);
		if (nonce[index] < 255) {
			nonce[index]++;
		}
		else {
			while (nonce[index] == 255 &&index==8) {
				nonce[index] = 0;
				index--;
			}
			if (index > 8)
			{
				nonce[index]++;
			}
			else
			{
				memset(nonce, 0, 8); //TO DO: PRNG TO REPLACE FIRST HALF OF NONCE
			}
		}
		index = AES_BLOCK_SIZE - 1;
		for (int j = 0; j < AES_BLOCK_SIZE; j++) {
			iv[j] ^= nonce[j];
		}
	}
	free(nonce);
	memcpy(iv, iv_aux, AES_BLOCK_SIZE);

}
void encrypt_aes_ofb(unsigned char* plaintext, int text_length, AES_KEY* aesKey, int keylength, unsigned char* iv, unsigned char** ciphertext) {
	(*ciphertext) = (unsigned char*)malloc(sizeof(unsigned char) * text_length);
	int blckNumber = text_length / AES_BLOCK_SIZE;
	unsigned char iv_aux[AES_BLOCK_SIZE];
	memcpy(iv_aux, iv,AES_BLOCK_SIZE);
	unsigned char inBlck[AES_BLOCK_SIZE];
	for (int i = 0; i < blckNumber; i++) {
		unsigned char outBlck[AES_BLOCK_SIZE];
		AES_encrypt(iv, outBlck, aesKey);
		memcpy(iv, outBlck, AES_BLOCK_SIZE);
		memcpy(inBlck, plaintext + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		for (int j = 0; j < AES_BLOCK_SIZE; j++) {
			outBlck[j] += 5;
			outBlck[j] ^= inBlck[j];
		}
		memcpy((*ciphertext + i *AES_BLOCK_SIZE), outBlck, AES_BLOCK_SIZE);
	}
	memcpy(iv, iv_aux, AES_BLOCK_SIZE);

}
void encrypt_rc4(unsigned char* plaintext,int input_length, unsigned char* key,int keylength,unsigned char** output) {
	unsigned char S[256];
	(*output) = (unsigned char*)malloc(sizeof(unsigned char) * input_length);
	int i, j = 0;
	for (i = 0; i <256; i++) {
		S[i] = i;
	}
	for (int i = 0; i < 256; i++) {
		j = (j + S[i] + key[i%keylength]) % 256;
		char aux = S[i];
		S[i] = S[j];
		S[j] = aux;
	}
	i = j = 0;
	for(int index=0;index<input_length;index++)
	{
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		char aux = S[i];
		S[i] = S[j];
		S[j] = aux;
		int t = (S[i] + S[j]) % 256;
		unsigned char k = S[t];
		(*output)[index] = plaintext[index] ^ k;
	}

}
void encrypt_3des(unsigned char *input,int input_length,unsigned char *userKey,int keylength,unsigned char * salt,int count) {
	//EVP_BytesToKey(EVP_des_ede3(), EVP_sha1(), salt, userKey, keylength / 2, count, key, ivec);
	int dkLen = 3*8; //8 - byte size of DES key
	unsigned char iv[100];
	unsigned char *DK=(unsigned char *)malloc(sizeof(unsigned char)*dkLen);
	EVP_BytesToKey(EVP_des_ede3(), EVP_sha1(), NULL, userKey, keylength / 2, count, DK, iv);
	DES_cblock key1, key2, key3;
	DES_key_schedule ks1,ks2,ks3;
	memcpy(key1, DK, 8);
	memcpy(key2, DK + 8, 8);
	memcpy(key3, DK + 16, 8);
	DES_set_odd_parity(&key1);
	DES_set_odd_parity(&key2);
	DES_set_odd_parity(&key3);
	printf("KEY 1 WEAK: %d\n",DES_set_key_checked(&key1, &ks1));
	printf("KEY 2 WEAK: %d\n", DES_set_key_checked(&key2, &ks2));
	printf("KEY 3 WEAK: %d\n", DES_set_key_checked(&key3, &ks3));
	int blckNumber = input_length / 8;
	for (int i = 0; i < blckNumber; i++) {
		DES_cblock inBlck,outBlck,plaintext;
		memcpy(inBlck, input + i * 8, 8);
		DES_ecb3_encrypt(&inBlck, &outBlck, &ks1, &ks2, &ks3, DES_ENCRYPT);
		DES_ecb3_encrypt(&outBlck, &plaintext, &ks1, &ks2, &ks3, DES_DECRYPT);
		for (int j = 0; j < 8; j++) {
			printf("%02x ", outBlck[j]);
		}
		printf("\t");
		for (int j = 0; j < 8; j++) {
			printf("%02x ", plaintext[j]);
			
		}
		printf("\n");
	}
}

int main() {
	//I USE file.key, file.iv and text.txt as tests
	char keyfile[20];
	printf("Introduceti numele fisierului in care se afla cheia: ");
	scanf("%s", keyfile);
	char ivfile[20];
	printf("Introduceti numele fisierului in care se afla IV-ul: ");
	scanf("%s", ivfile);
	char textfile[20];
	printf("Introduceti numele fisierului in care se afla plaintext-ul: ");
	scanf("%s", textfile);
	AES_KEY aesKey,decKey;
	int keylength,ivlength;
	unsigned char* userKey = readStringFromFile(keyfile,&keylength);
	printf("Lungimea cheii este : %d bytes.\n", keylength/2);

	AES_set_encrypt_key(userKey, keylength * 4, &aesKey);
	AES_set_decrypt_key(userKey, keylength * 4, &decKey);
	unsigned char* iv = readStringFromFile(ivfile, &ivlength);
	printf("Lungimea IV este : %d bytes.\n", ivlength/2);
	unsigned char* cbc_ciphertext=nullptr;
	unsigned char* cbc_recovered = nullptr;
	unsigned char* ctr_ciphertext = nullptr;
	unsigned char* ctr_recovered = nullptr;
	unsigned char* ofb_ciphertext = nullptr;
	unsigned char* ofb_recovered = nullptr;
	unsigned char* rc4_ciphertext = nullptr;
	unsigned char* rc4_recovered = nullptr;
	int cipher_length;
	int blckNumber;
	if (ivlength/2 == AES_BLOCK_SIZE && (keylength/2) % AES_BLOCK_SIZE == 0)
	{
		encrypt_aes_cbc(textfile, &aesKey, keylength,iv, &cbc_ciphertext,&cipher_length);
		blckNumber= cipher_length / AES_BLOCK_SIZE;
		decrypt_aes_cbc(cbc_ciphertext, cipher_length, &decKey, keylength, iv, &cbc_recovered);
		printf("\nAES-%d-CBC ENCRYPTION:\n", keylength * 4);
		for (int i = 0; i < blckNumber; i++) {
			for (int j = 0; j < AES_BLOCK_SIZE; j++) {
				printf("%02x ", cbc_ciphertext[i * AES_BLOCK_SIZE + j]);
			}
			printf("\t");
			for (int j = 0; j < AES_BLOCK_SIZE; j++) {
				printf("%02x ", cbc_recovered[i * AES_BLOCK_SIZE + j]);
			}
			printf("\n");
		}
		encrypt_aes_ctr(cbc_recovered, cipher_length, &aesKey, keylength, iv, &ctr_ciphertext);
		encrypt_aes_ctr(ctr_ciphertext, cipher_length, &aesKey, keylength, iv, &ctr_recovered);
		printf("\nAES-%d-CTR ENCRYPTION:\n", keylength * 4);
		for (int i = 0; i < blckNumber; i++) {
			for (int j = 0; j < AES_BLOCK_SIZE; j++) {
				printf("%02x ", ctr_ciphertext[i * AES_BLOCK_SIZE + j]);
			}
			printf("\t");
			for (int j = 0; j < AES_BLOCK_SIZE; j++) {
				printf("%02x ", ctr_recovered[i * AES_BLOCK_SIZE + j]);
			}
			printf("\n");
		}
		encrypt_aes_ofb(cbc_recovered, cipher_length, &aesKey, keylength, iv, &ofb_ciphertext);
		encrypt_aes_ofb(ofb_ciphertext, cipher_length, &aesKey, keylength, iv, &ofb_recovered);
		printf("\nAES-%d-OFB ENCRYPTION:\n", keylength * 4);
		for (int i = 0; i < blckNumber; i++) {
			for (int j = 0; j < AES_BLOCK_SIZE; j++) {
				printf("%02x ", ofb_ciphertext[i * AES_BLOCK_SIZE + j]);
			}
			printf("\t");
			for (int j = 0; j < AES_BLOCK_SIZE; j++) {
				printf("%02x ", ofb_recovered[i * AES_BLOCK_SIZE + j]);
			}
			printf("\n");
		}
	}
	encrypt_rc4(cbc_recovered, cipher_length, userKey, keylength/2,&rc4_ciphertext);
	encrypt_rc4(rc4_ciphertext, cipher_length, userKey, keylength / 2, &rc4_recovered);
	printf("\nRC4 ENCRYPTION: \n");
	for (int i = 0; i < blckNumber; i++) {
		for (int j = 0; j < AES_BLOCK_SIZE; j++) {
			printf("%02x ", rc4_ciphertext[i*AES_BLOCK_SIZE+j]);
		}
		printf("\t");
		for (int j = 0; j < AES_BLOCK_SIZE; j++) {
			printf("%02x ", rc4_recovered[i * AES_BLOCK_SIZE + j]);
		}
		printf("\n");
	}
	unsigned char key[100];
	unsigned char ivec[100];
	unsigned char salt[100];
	memset(salt, 0, ivlength / 2);
	printf("\n3-DES ENCRYPTION:\n");
	encrypt_3des(cbc_recovered,cipher_length, userKey, keylength, salt, 1);	
	return 0;
}