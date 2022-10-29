#include "aes_config.h"
#include "aes.h"

void EncryptBlock(uint8_t* block) {
	AddRoundKey(block, 0);
	for (uint8_t i = 1; i < 10; i++)
	{
		SubBytes(block);
		ShiftRowsLeft(block);
		MixColumns(block);
		AddRoundKey(block, i);
	}
	SubBytes(block);
	ShiftRowsLeft(block);
	AddRoundKey(block, 10);
}

void EncryptStreamOrigin(uint8_t* stream, size_t length) {
	size_t blcks = length / 16;
	for (size_t i = 0; i < blcks; i++) 
		EncryptBlock(stream + i * 16);
}

void EncryptStream(uint8_t* src, uint8_t* dst, uint32_t length) {
	memcpy(dst, src, length);
	EncryptStreamOrigin(dst, length);
}

uint8_t* Encrypt(uint8_t* src, size_t length, size_t* streamLength) {
	if (src == NULL || length < 1)	return NULL;		//Define error	->	NULL src or length

	*streamLength = length + ((length & 0x0F) == 0 ? 0x10 : 16 - (length & 0x0F));
	
	uint8_t* dstStream = malloc(*streamLength * sizeof(uint8_t));
	if (dstStream == NULL)	return dstStream;			//Define error	->	Mem. allocation falied

	memcpy(dstStream, src, length);

	//Padding the data with #PKCS7
	for (size_t i = (*streamLength) - 1; i >= length; i--)
		dstStream[i] = ((length & 0x0F) == 0 ? 0x10 : 16 - (length & 0x0F));

	EncryptStreamOrigin(dstStream, *streamLength);

	return dstStream;
}

// ----------

void DecryptBlock(uint8_t* block) {
	AddRoundKey(block, 10);
	for (uint8_t i = 9; i > 0; i--) {
		ShiftRowsRight(block);
		SubBytesInv(block);
		AddRoundKey(block, i);
		MixColumnsInv(block);
	}
	ShiftRowsRight(block);
	SubBytesInv(block);
	AddRoundKey(block, 0);

}

void DecryptStreamOrigin(uint8_t* stream, uint32_t length) {
	uint32_t blcks = length / 16;
	for (uint32_t i = 0; i < blcks; i++)
		DecryptBlock(stream + i * 16);
}

void DecryptStream(uint8_t* src, uint8_t* dst, uint32_t length) {
	memcpy(dst, src, length);
	DecryptStreamOrigin(dst, length);
}

uint8_t* Decrypt(uint8_t* src, size_t length, size_t* streamLength) {
	if (src == NULL || length < 0) return NULL;		//Define error	->	NULL src or length

	if (length & 0x0F != 0)	return NULL;			//Define error	->	Bad stream size
		

	uint8_t* dstStream = malloc(length);
	if (dstStream == NULL)	return dstStream;		//Define error	->	Mem. allocation falied

	memcpy(dstStream, src, length);

	DecryptStreamOrigin(dstStream, length);

	*streamLength = length - (dstStream[length - 1] == 0x10 ? 0x10 : dstStream[length - 1]);

	return dstStream;
}

//

uint8_t SubByteSingle(uint8_t byte) {
	return sBox[byte >> 4][byte & 0x0F];
}

void SubBytes(uint8_t* block) {
	for (uint8_t i = 0; i < 16; i++)
		*(block++) = sBox[*block >> 4][*block & 0x0F];
}

void SubBytesInv(uint8_t* block) {
	for (uint8_t i = 0; i < 16; i++)
		*(block++) = sBoxInv[*block >> 4][*block & 0x0F];
}

void ShiftRowsLeft(uint8_t* block) {
	procArray[0] = block[0];
	procArray[1] = block[5];
	procArray[2] = block[10];
	procArray[3] = block[15];
	procArray[4] = block[4];
	procArray[5] = block[9];
	procArray[6] = block[14];
	procArray[7] = block[3];
	procArray[8] = block[8];
	procArray[9] = block[13];
	procArray[10] = block[2];
	procArray[11] = block[7];
	procArray[12] = block[12];
	procArray[13] = block[1];
	procArray[14] = block[6];
	procArray[15] = block[11];
	memcpy(block, procArray, 16);
}

void ShiftRowsRight(uint8_t* block) {
	procArray[0] = block[0];
	procArray[1] = block[13];
	procArray[2] = block[10];
	procArray[3] = block[7];
	procArray[4] = block[4];
	procArray[5] = block[1];
	procArray[6] = block[14];
	procArray[7] = block[11];
	procArray[8] = block[8];
	procArray[9] = block[5];
	procArray[10] = block[2];
	procArray[11] = block[15];
	procArray[12] = block[12];
	procArray[13] = block[9];
	procArray[14] = block[6];
	procArray[15] = block[3];
	memcpy(block, procArray, 16);
}

void MixColumns(uint8_t* block) {
	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t mult = 0; mult < 4; mult++)
			procArray[i * 4 + mult] = GFMult(constMatrix[mult][0], block[i * 4]) ^ GFMult(constMatrix[mult][1], block[i * 4 + 1]) ^ GFMult(constMatrix[mult][2], block[i * 4 + 2]) ^ GFMult(constMatrix[mult][3], block[i * 4 + 3]);
	memcpy(block, procArray, 16);	
}

void MixColumnsInv(uint8_t* block) {
	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t mult = 0; mult < 4; mult++)
			procArray[i * 4 + mult] = GFMult(constMatrixInv[mult][0], block[i * 4]) ^ GFMult(constMatrixInv[mult][1], block[i * 4 + 1]) ^ GFMult(constMatrixInv[mult][2], block[i * 4 + 2]) ^ GFMult(constMatrixInv[mult][3], block[i * 4 + 3]);
	memcpy(block, procArray, 16);
}
/*
uint8_t GaloisFieldMult(uint8_t multiplier, uint8_t mutiplicant) {

}
*/
uint8_t GFMult(uint8_t multiplier, uint16_t multiplicant) {
	switch (multiplier)
	{
	case 1:
		return multiplicant;
	case 2:
		multiplicant = multiplicant << 0x01;
		break;
	case 3:
		multiplicant = multiplicant ^ (multiplicant << 0x01);
		break;
	case 9:
		return mul_9[multiplicant];
	case 11:
		return mul_11[multiplicant];
	case 13:
		return mul_13[multiplicant];
	case 14:
		return mul_14[multiplicant];
	default:
		return NULL;
	}
	return (uint8_t)(multiplicant >= GF_MULT_OVERFLOW ? (multiplicant - GF_MULT_OVERFLOW) ^ 0x1B : multiplicant);
}

void AddRoundKey(uint8_t* block, uint8_t keyNum) {

	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t j = 0; j < 4; j++)
			block[j * 4 + i] = block[j * 4 + i] ^ cryptoKex[keyNum][i * 4 + j];
}

void ExpandKey(uint8_t* srcKey, uint8_t* dstKey, uint8_t keyNum) {
	dstKey[0] = SubByteSingle(srcKey[7]) ^ srcKey[0] ^ rcon_table[keyNum];
	dstKey[4] = SubByteSingle(srcKey[11]) ^ srcKey[4];
	dstKey[8] = SubByteSingle(srcKey[15]) ^ srcKey[8];
	dstKey[12] = SubByteSingle(srcKey[3]) ^ srcKey[12];
	for (uint8_t i = 1; i < 4; i++) {
		dstKey[i] = dstKey[i - 1] ^ srcKey[i];
		dstKey[i + 4] = dstKey[i + 3] ^ srcKey[i + 4];
		dstKey[i + 8] = dstKey[i + 7] ^ srcKey[i + 8];
		dstKey[i + 12] = dstKey[i + 11] ^ srcKey[i + 12];
	}
}

void CalculateKeys(const char* key) {

	if (strlen(key) != 0x10)	return;		//Just let this go for now pls... °~°

	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t j = 0; j < 4; j++)
			cryptoKex[0][j * 4 + i] = key[i * 4 + j];
	for (uint8_t i = 1; i < 11; i++)
		ExpandKey(cryptoKex[i - 1], cryptoKex[i], i - 1);
}