#ifdef WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif
#define _CRT_SECURE_NO_WARNINGS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>

#include<stdio.h>
#include<conio.h>
#include<string.h>
#include <math.h>
#include<stdlib.h>
#include<openssl/rand.h>
#include<openssl/aes.h>
#include<openssl/des.h>

//Dimensiune salt,IV si cheie in octeti
#define _KEY_BYTE_LENGTH 32
#define _IV_BYTE_LENGTH 16
#define _IO_ERROR 1
int loadKeyFromFile(char* filename, unsigned char** userkey,int&keylength)
{
	int length;
	FILE* keyFile = fopen(filename, "rb");
	if (keyFile == NULL)
	{
		printf("Nu s-a putut deschide fisierul %s !\n", filename);
		return 1;
	}

	// determin lungimea fisierului unde se afla cheia
	fseek(keyFile, 0, SEEK_END);
	length = ftell(keyFile);
	rewind(keyFile);
	keylength = length;
	if (length != _KEY_BYTE_LENGTH*2)
	{
		printf("Dimensiune invalida a cheii din fisierul %s\n", filename);
		return 1;
	}

	//citesc cheia in buffer-ul userkey pentru a avea acces la ea din main
	(*userkey) = (unsigned char*)malloc(sizeof(unsigned char) * (length/2));
	for (int i = 0; i < _KEY_BYTE_LENGTH; i++) {
		fscanf(keyFile, "%02x", &(*userkey)[i]);
	}
	fclose(keyFile);
	return 0;
}

/* incarca IV din fisier */
int loadIVFromFile(char* filename, unsigned char** iv,int&ivlength)
{
	int length;
	FILE* ivFile = fopen(filename, "rb");
	if (ivFile == NULL)
	{
		printf("Nu s-a putut deschide fisierul %s !\n", filename);
		return 1;
	}

	// determin lungimea fisierul unde se afla IV-ul
	fseek(ivFile, 0, SEEK_END);
	length = ftell(ivFile);
	rewind(ivFile);
	ivlength = length;
	if ((length/2) != _IV_BYTE_LENGTH)
	{
		printf("Dimensiune invalida a vectorului de initializare din fisierul %s\n", filename);
		return 1;
	}

	//salvez vectorul de initializare in iv pt a avea acces la el din main
	(*iv) = (unsigned char*)malloc(sizeof(unsigned char) * (length/2));
	for (int i = 0; i < _IV_BYTE_LENGTH; i++) {
		fscanf(ivFile, "%02x", &(*iv)[i]);
	}
	fclose(ivFile);
	return 0;
}
int loadPlaintextFromFile(char* filename, unsigned char** pData, int& pLength) {
	int length;
	FILE* plainFile = fopen(filename, "rb");
	if (plainFile == NULL) {
		printf("Nu s-a putut deschide fisierul %s !\n", filename);
		return 1;
	}
	fseek(plainFile, 0L, SEEK_END);
	length = ftell(plainFile);
	rewind(plainFile);
	pLength = length;
	if (!pLength) {
		printf("Fisierul care contine textul care va fi criptat nu poate fi gol !\n");
		return 1;
	}
	(*pData) = (unsigned char*)malloc(sizeof(unsigned char) * length);
	fread((*pData), 1, length, plainFile);
	fclose(plainFile);
	return 0;
}
int _add_padding(unsigned char** data, int& dataLen, int blockSize)
{
	//determin numarul de octeti necesari pt padding
	int padblk_nr = blockSize - (dataLen % blockSize);

	//daca ultimul bloc este complet atunci mai aloc memorie pentru un bloc intreg cu fiecare octet 0x10
	if (padblk_nr == 0)
	{
		dataLen += blockSize;
		(*data) = (unsigned char*)realloc(*data, dataLen);
		if (*data == NULL)
			return 1;

		for (int i = 1; i <= blockSize; i++)
			(*data)[dataLen - i] = blockSize;
	}

	else
		//altfel aloc memorie pt inca padblk_nr octeti cu valoare padblk_nr
	{
		dataLen += padblk_nr;
		(*data) = (unsigned char*)realloc(*data, dataLen);
		if (*data == NULL)
			return  1;

		for (int i = 1; i <= padblk_nr; i++)
			(*data)[dataLen - i] = padblk_nr;
	}
	return 0;
}
void _increment_counter(unsigned char* counter, int position)
{
	if (position < 0)
		return;

	/*daca octectul curent are valoare 0xFF atunci apelez recursiv functia pentru octetul urmator mai semnificativ*/
	if (counter[position] == 0xFF)
	{
		counter[position] = 0x00;
		_increment_counter(counter, position - 1);
		return;
	}
	counter[position] ++;
	return;
}
int readDataFromKeyboard(unsigned char** data, int& dataLen)
{
	char ch;
	dataLen = 0;
	(*data) = (unsigned char*)malloc(0);

	fflush(stdin);
	printf("Introduceti datele: ");
	do
	{
		ch = _getch();
		if (ch == 13)
			break;
		printf("%c", ch);

		dataLen++;
		(*data) = (unsigned char*)realloc(*data, dataLen);

		if ((*data) == NULL)
			return 1;
		(*data)[dataLen - 1] = ch;
	} while (ch != 13);
	(*data)[dataLen] = 0;
	if (dataLen >= 64) {
		return 1;
	}
	printf("\n");
	return 0;
}

int _aes_encrypt_cbc(unsigned char** pData, int& dataLen, unsigned char* iv, unsigned char** userkey, unsigned char** encData)
{
	int status = 0;
	AES_KEY aesKey;
	unsigned char inblk[AES_BLOCK_SIZE], outblk[AES_BLOCK_SIZE];
	int offset = 0;

	status = AES_set_encrypt_key((*userkey), _KEY_BYTE_LENGTH * 8, &aesKey);
	if (status != 0)
		return status;

	(*encData) = (unsigned char*)malloc(dataLen);
	if (*encData == NULL)
		return 1;
	unsigned char* iv_temp = (unsigned char*)malloc(AES_BLOCK_SIZE * sizeof(unsigned char));
	memcpy(iv_temp, iv, AES_BLOCK_SIZE);
	//criptez  AES CBC fiecare bloc 
	while (offset < dataLen)
	{
		memcpy(inblk, (*pData) + offset, AES_BLOCK_SIZE);
		//fac XOR intre IV si blocul de intrare 
		for (int i = 0; i < AES_BLOCK_SIZE; i++)
			inblk[i] = inblk[i] ^ iv_temp[i];

		AES_encrypt(inblk, outblk, &aesKey);
		memcpy((*encData) + offset, outblk, AES_BLOCK_SIZE);

		//copiez in bufferul iv ciphertext-ul curent pt a face XOR cu urmatorul bloc de intrare 
		memcpy(iv_temp, outblk, AES_BLOCK_SIZE);
		offset += AES_BLOCK_SIZE;
	}
	free(iv_temp);
	return 0;
}
void blockMultiplication(unsigned char* X, unsigned char* Y) {
	unsigned char* Z = (unsigned char*)calloc(AES_BLOCK_SIZE,sizeof(unsigned char));
	unsigned char* R = (unsigned char*)malloc(AES_BLOCK_SIZE * sizeof(unsigned char));
	R[0] = 225;
	for (int i = 1; i < AES_BLOCK_SIZE; i++) {
		R[i] = 0;
	}
	unsigned char* V = (unsigned char*)malloc(AES_BLOCK_SIZE * sizeof(unsigned char));
	memcpy(V, Y, AES_BLOCK_SIZE);

	for (int i = 0; i < AES_BLOCK_SIZE; i++) {
		int value = X[i];
		int m = 1;
		for (int j = 0; j < 8; j++) {
			if (value % 2 == 1) {
				for (int l = 0; l < AES_BLOCK_SIZE; l++)
				{
					Z[l] ^= V[l];
				}
			}
			if (V[AES_BLOCK_SIZE - i - 1] % 2 == 0) {
				V[AES_BLOCK_SIZE - i - 1] >>= 1;
			}
			else
			{
				V[AES_BLOCK_SIZE - i - 1] >>= 1;
				for (int l = 0;l < AES_BLOCK_SIZE; l++) {
					V[l] ^= R[l];
				}
			}
		}
	}
	memcpy(X, Z, AES_BLOCK_SIZE);
	free(Z);
	free(V);
	free(R);
}
unsigned char * ghash(unsigned char *X,int &x_length,unsigned char *H) {
	unsigned char* Y = (unsigned char*)calloc(16, sizeof(unsigned char));
	for (int i = 0; i < x_length / AES_BLOCK_SIZE; i++) {
		unsigned char inBlck[AES_BLOCK_SIZE];
		unsigned char outBlck[AES_BLOCK_SIZE];
		memcpy(inBlck, X + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
		for (int j = 0; j < AES_BLOCK_SIZE; j++) {
			outBlck[j] = Y[j] ^ inBlck[j];
		}
		blockMultiplication(outBlck, H);
		memcpy(Y, outBlck, AES_BLOCK_SIZE);
	}
	return Y;
}
void defineInitialBlock(unsigned char* iv, int& iv_length,unsigned char **j,int &j_length) {
	if (iv_length == 12) {
		(*j) = (unsigned char*)malloc(AES_BLOCK_SIZE * sizeof(unsigned char));
		memcpy((*j), iv, iv_length);
		memset(*(j + iv_length), 0, 3);
		memset(*(j + iv_length+3), 1, 1);
		j_length = 16;
	}
	else {
		int s;
		float rest = iv_length / 16;
		if (rest == (int)rest) {
			s = (int)rest;
		}
		else {
			s = (int)rest;
			s += 1;
		}
		s *= 16;
		s -= iv_length;
		(*j) = (unsigned char*)malloc(iv_length + s + 16);
		memcpy((*j), iv, iv_length);
		for (int i = 0; i < s + 8; i++) {
			(*j)[iv_length + i] = 0;
		}
		int size_in_bits = iv_length * 8;
		int index = 15;
		while (size_in_bits) {
			(*j)[iv_length + s + 8 + index] = size_in_bits % 256;
			size_in_bits >>= 8;
		}
		for (int i = 0; i <= index; i++) {
			(*j)[iv_length + s + 8 + i] = 0;
		}
		j_length = 32;
	}
}
void gctr(unsigned char* key,unsigned char * cb,unsigned char *pData,int pLen,unsigned char **encData,unsigned char *iv) {
	int n;
	float rest = (float)pLen / 16;
	if (rest == (int)rest) n = (int)rest;
	else n = (int)rest + 1;
	(*encData) = (unsigned char*)malloc(sizeof(unsigned char) * pLen);
	AES_KEY aesKey;
	unsigned char inblk[AES_BLOCK_SIZE], outblk[AES_BLOCK_SIZE];

	int status = AES_set_encrypt_key(key, _KEY_BYTE_LENGTH * 8, &aesKey);
	for (int i = 0; i < n; i++) {
		unsigned char* inBlck = (unsigned char*)malloc(AES_BLOCK_SIZE * sizeof(unsigned char));
		unsigned char* outBlck = (unsigned char*)malloc(AES_BLOCK_SIZE * sizeof(unsigned char));
		int size = 16;
		AES_encrypt(cb, outBlck, &aesKey);
		for (int j = 0; j < AES_BLOCK_SIZE; j++) {
			outBlck[j] ^= pData[i*AES_BLOCK_SIZE+j];
		}
		for (int index = AES_BLOCK_SIZE - 1; index >= AES_BLOCK_SIZE - 4;) {
			if (cb[index] == 0xFF) {
				cb[index] = 0;
				index--;
			}
			else {
				cb[index]++;
				break;
			}
		}
		memcpy((*encData + i * AES_BLOCK_SIZE), outBlck, AES_BLOCK_SIZE);
	}
}
int _gcm_encrypt(char *p_file,char *key_file,char*iv_file,int tag_length,unsigned char**tag,unsigned char **encData,int &text_length,int flag) {
	unsigned char* key = nullptr, * iv = nullptr, * data = nullptr, * pData = nullptr;
	int key_length, iv_length,data_length,plain_length;
	int status = loadKeyFromFile(key_file, &key,key_length);
	if (status != 0) {
		return _IO_ERROR;
	}
	status = loadPlaintextFromFile(p_file, &pData, plain_length);
	if (status != 0) {
		return _IO_ERROR;
	}
	status = loadIVFromFile(iv_file, &iv, iv_length);
	if (status != 0) {
		return _IO_ERROR;
	}
	status = readDataFromKeyboard(&data, data_length);
	if (status != 0) {
		return _IO_ERROR;
	}
	printf("Cheie (caractere HEX): ");
	for (int i = 0; i < _KEY_BYTE_LENGTH; i++) {
		printf("%02x", key[i]);
	}
	printf("\nIV (caractere HEX): ");
	for (int i = 0; i < _IV_BYTE_LENGTH; i++) {
		printf("%02x", iv[i]);
	}
	printf("\nAuthData (caractere ASCII, lungime < 64 caractere): ");
	printf("%s\nText Clar (caractere ASCII): ", data);
	for (int i = 0; i < plain_length; i++) {
		printf("%02x ", pData[i]);
	}
	text_length = plain_length;
	_add_padding(&pData, plain_length, AES_BLOCK_SIZE);
	//am datele, acum incep desfasurarea algoritmului
	// step 1: crearea blocului H = CIPH(key,0^128);
	unsigned char* block_zero = (unsigned char*)calloc(16,sizeof(unsigned char));
	int block_length = 16;
	unsigned char* H=nullptr;
	_aes_encrypt_cbc(&block_zero, block_length, iv, &key, &H);
	printf("\n");
	for (int i = 0; i < block_length; i++) {
		printf("%02x ", H[i]);
	}
	//step 2: definirea blocului J0 in functie de lungimea IV
	printf("\n");
	unsigned char* J = nullptr;
	int j_length;
	if (iv_length == _IV_BYTE_LENGTH) {
		J = (unsigned char*)malloc(_IV_BYTE_LENGTH * sizeof(unsigned char));
		memcpy(J, iv, _IV_BYTE_LENGTH);
		j_length = _IV_BYTE_LENGTH;
	}
	else {
		defineInitialBlock(iv, iv_length, &J, j_length);
	}
	//step 3: get ciphertext C=GCTR(K,inc32(J),P)
	unsigned char* icb = (unsigned char*)malloc(AES_BLOCK_SIZE * sizeof(unsigned char));
	memcpy(icb, J, AES_BLOCK_SIZE);
	for (int index = AES_BLOCK_SIZE - 1; index >= AES_BLOCK_SIZE - 4;) {
		if (icb[index] == 0xFF) {
			icb[index] = 0;
			index--;
		}
		else {
			icb[index]++;
			break;
		}
	}
	gctr(key, icb, pData, plain_length, encData, iv);
	//step 4: get u and v
	int u, v;
	float rest = (float)plain_length / 16;
	if ((int)rest == rest) u = 16*(int)rest-plain_length;
	else u = 16*((int)rest + 1)-plain_length;
	rest = (float)data_length / 16;
	if ((int)rest == rest) v = 16 * (int)rest - data_length;
	else v = 16 * ((int)rest + 1) - data_length;
	//step 5: define S=ghash(pData || 0^v || encData || 0^u || data_length || plain_length); 
	unsigned char* S = (unsigned char*)malloc(sizeof(unsigned char) * (data_length + v + plain_length + u + 16));
	memcpy(S, data, data_length);
	for (int index = data_length; index < data_length+ v; index++) {
		S[index] = 0;
	}
	if (flag == 1) {
		memcpy(S + data_length + v, *encData, plain_length);
	}
	else if (flag == 0) {
		memcpy(S + data_length + v, pData, plain_length);
	}
	for (int index = data_length+v+plain_length; index < data_length + v + plain_length+ u; index++) {
		S[index] = 0;
	}
	int size_in_bits = data_length * 8;
	for (int i = data_length + v + plain_length + u + 7; i >= data_length + v + plain_length + u; i--) {
		S[i] = size_in_bits % 256;
		size_in_bits >>= 8;
	}
	size_in_bits = plain_length * 8;
	for (int i = data_length + v + plain_length + u + AES_BLOCK_SIZE - 1; i >= data_length + v + plain_length + u+8; i--) {
		S[i] = size_in_bits % 256;
		size_in_bits >>= 8;
	}
	printf("\nBlocul S = ");
	for (int i = 0; i < data_length + v + plain_length + u + 16; i++)
	{
		printf("%02x ", S[i]);
	}
	unsigned char* S1 = (unsigned char*)malloc(sizeof(unsigned char) * (data_length + v + plain_length + u + 16));
	int s_length= data_length + v + plain_length + u + 16;
	S1 = ghash(S, s_length, H);
	printf("\nAuthetification Tag: ");
	gctr(key, J, S1, data_length + v + plain_length + u + 16, tag, iv);
	for (int i = 0; i < tag_length; i++) {
		printf("%02x ", (*tag)[i]);
	}
	char outFile[30];
	printf("\nIntroduceti numele fisierului in care se va salva rezultatul: ");
	scanf("%s", outFile);
	FILE* out = fopen(outFile, "w");
	fwrite((*encData), 1, text_length, out);
	fclose(out);

}
unsigned char* int2hex(unsigned int number) {
	unsigned char *newValue=(unsigned char*)malloc(4*sizeof(unsigned char));
	int i;
	for (i = 3; i >= 0; i--) {
		newValue[i] = number % 256;
		number >>= 8;
	}
	return newValue;
}
unsigned int hex2int(unsigned char* vector) {
	unsigned int value = 0;
	for (int i = 0; i < 4; i++) {
		value <<= 8;
		value += vector[i];
	}
	return value;
}
void bc4_decrypt() {
	unsigned char encData[] = { 0xED,0xA1,0xE0,0xBC, //encBlock0 = Z0 ^ plainBlock0 ;
								0xE1,0x9B,0xDE,0x66, //encBlock1 = Z1 ^ plainBlock1 ;
								0x5D,0xD6,0x2D,0x3C, //encBlock2 = Z2 ^ plainBlock2 ;
								0x9A,0x1C,0x30,0x01, // ...
								0xDC,0x52,0x3A,0x07,
								0xFA,0xB5,0xC8,0xC1,
								0x5F,0xF2,0xC0,0xEA,
								0xB4,0x82,0xE3,0xA3,
								0x7D,0x63,0x89,0xDF,
								0xA0,0xB4,0x58,0xCA,
								0xE5,0x35,0xB8,0x41,
								0xF2,0x4D,0x8A,0x2A,
								0xE7,0x36,0x1B,0x1D,
								0x16,0xAB,0xD2,0x03,
								0x13,0x67,0xC3,0xBD,
								0xFA,0x7B,0xE2,0x12,
								0x50,0x36,0x1C,0xC5,
								0xD2,0x3C,0x38,0x03,
								0xEE,0x95,0xB4,0x34,
								0x27,0x94,0xFB,0x74,
								0x96,0x45,0xE2 };
	int size = sizeof(encData) /4;
	unsigned char* plainData = (unsigned char*)malloc(sizeof(unsigned char) * sizeof(encData));
	unsigned char plainBlock0[4] = { 0x74, 0x68, 0x69, 0x73 }; //	this
	unsigned char plainBlock1[4] = { 0x20, 0x77, 0x69, 0x6c }; //	' 'wil
	unsigned char plainBlock2[4] = { 0x6c, 0x20, 0x62, 0x65 }; //	l' 'be

	unsigned char z0[4], z1[4], z2[4];
	int i;
	printf("z0 z1 z2\n");
	for (i = 0; i < 4; i++) {
		z0[i] = plainBlock0[i] ^ encData[i];
		z1[i] = plainBlock1[i] ^ encData[4 + i];
		z2[i] = plainBlock2[i] ^ encData[8 + i];
		printf("%02x %02x %02x\n", z0[i], z1[i], z2[i]);
	}
	unsigned int index = 0;
	//aflarea cheii
	unsigned int left_value = 2300000000, right_value = 0;
	unsigned int P = 3525886283;
	while (left_value<UINT32_MAX) {
		int wrong = 0;
		unsigned char* left0 = int2hex(left_value);
		unsigned char right0[4];
		for (int i = 0; i < 4; i++) {
			right0[i] = z0[i] ^ left0[i];
		}
		right_value = hex2int(right0);
		unsigned long long temp1 = (unsigned long long) 5 * left_value + 11;
		unsigned long long temp2 = (unsigned long long) 7 * right_value + 19;
		unsigned int l1 = temp1 % P;
		unsigned int r1 = temp2 % P;
		unsigned char* left1 = int2hex(l1);
		unsigned char* right1 = int2hex(r1);
		unsigned int z1_value = hex2int(z1);
		int equal = 0;
		if (z1_value == (l1 ^ r1)) {
			temp1 = (unsigned long long) 5 * l1 + 11;
			temp2 = (unsigned long long) 7 * r1 + 19;
			unsigned int l2 = temp1 % P;
			unsigned int r2 = temp2 % P;
			unsigned int z2_value = hex2int(z2);
			if (z2_value == (l2 ^ r2)) {
				printf("FOUND: %u %u.\n", left_value, right_value);
				break;
			}
		}
		if (left_value % 1000000000==0) printf("Milestone: %u\n",left_value);
		left_value++;
		free(left0);
		free(left1);
		free(right1);
	}
	for (int i = 0; i <= size; i++) {
		unsigned char inBlck[4];
		unsigned char z[4];
		unsigned char* left = int2hex(left_value);
		unsigned char* right = int2hex(right_value);
		memcpy(inBlck, encData+i*4, 4);
		printf("L%d: ", i);
		for (int i = 0; i < 4; i++) {
			printf("%02x ", left[i]);
		}
		printf("\nR%d: ",i);
		for (int i = 0; i < 4; i++) {
			printf("%02x ", right[i]);
		}
		printf("\n");
		if (i == size) {
			for (int j = 0; j < sizeof(encData)-4*size; j++) {
				z[j] = left[j] ^ right[j];
				plainData[i*4+j] = inBlck[j] ^ z[j];
				//printf("%c", inBlck[j] ^ z[j]);
			}
		}
		else {
			for (int j = 0; j < 4; j++) {
				z[j] = left[j] ^ right[j];
				plainData[i*4+j] = inBlck[j] ^ z[j];
				//printf("%c", inBlck[j] ^ z[j]);
			}
		}
		unsigned long long temp1 = (unsigned long long) 5 * left_value + 11;
		unsigned long long temp2 = (unsigned long long) 7 * right_value + 19;
		left_value = temp1 % P;
		right_value = temp2 % P;
	}
	for (int i = 0; i < sizeof(encData); i++) {
		printf("%c", plainData[i]);
	}

	
	
}
int main() {
	char key_file[30];
	char iv_file[30];
	char pFile[30];
	printf("Introduceti fisierul din care se va citi cheia: ");
	scanf("%s", key_file);
	printf("Introduceti fisierul din care se va citi IV-ul: ");
	scanf("%s", iv_file);
	printf("Introduceti fisierul din care se va citi PLAINTEXT-ul: ");
	scanf("%s", pFile);
	unsigned char* tag = nullptr, * encData = nullptr;
	int tag_length,text_length;
	printf("Introduceti dimensiunea TAG-ului: ");
	scanf("%d", &tag_length);
	if (tag_length % 4 != 0) {
		printf("Dimensiune incorecta a tag-ului!\n");
		return _IO_ERROR;
	}
	int flag = 1;
	_gcm_encrypt(pFile,key_file,iv_file,tag_length,&tag,&encData,text_length,flag);
	unsigned char* tag_verify = nullptr, * plainData = nullptr;
	printf("Introduceti textul din care se va citi textul criptat: ");
	char eFile[30];
	scanf("%s", eFile);
	flag = 0;
	_gcm_encrypt(eFile, key_file, iv_file, tag_length, &tag_verify, &plainData, text_length,flag);
	for (int i = 0; i < tag_length; i++) {
		if (tag[i] != tag_verify[i]) {
			printf("Nu s-a putut realiza verificarea tag-ului!");
			return 1;
		}
	}
	printf("\nTextul decriptat: ");
	for (int i = 0; i < text_length; i++) {
		printf("%c", plainData[i]);
	}
	//bc4_decrypt();
}