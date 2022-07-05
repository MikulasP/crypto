#include "aes.h"

AES::AES(char* key) {
	CalculateKeys(key);
}

void AES::EncryptBlock(uint8_t* block) {
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

void AES::EncryptStream(uint8_t* stream, size_t length) {
	size_t blcks = length / 16;
	for (size_t i = 0; i < blcks; i++) 
		EncryptBlock(stream + i * 16);
}

void AES::DecryptBlock(uint8_t* block) {
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

void AES::DecryptStream(uint8_t* stream, size_t length) {
	size_t blcks = length / 16;
	for (size_t i = 0; i < blcks; i++)
		DecryptBlock(stream + i * 16);
}

uint8_t AES::SubByteSingle(uint8_t byte) {
	return sBox[byte >> 4][byte & 0x0F];
}

void AES::SubBytes(uint8_t* block) {
	for (uint8_t i = 0; i < 16; i++)
		*(block++) = sBox[*block >> 4][*block & 0x0F];
}

void AES::SubBytesInv(uint8_t* block) {
	for (uint8_t i = 0; i < 16; i++)
		*(block++) = sBoxInv[*block >> 4][*block & 0x0F];
}

void AES::ShiftRowsLeft(uint8_t* block) {
	procArray[0] = *block;
	procArray[1] = *(block + 5);
	procArray[2] = *(block + 10);
	procArray[3] = *(block + 15);
	procArray[4] = *(block + 4);
	procArray[5] = *(block + 9);
	procArray[6] = *(block + 14);
	procArray[7] = *(block + 3);
	procArray[8] = *(block + 8);
	procArray[9] = *(block + 13);
	procArray[10] = *(block + 2);
	procArray[11] = *(block + 7);
	procArray[12] = *(block + 12);
	procArray[13] = *(block + 1);
	procArray[14] = *(block + 6);
	procArray[15] = *(block + 11);
	std::memcpy(block, procArray, 16);
}

void AES::ShiftRowsRight(uint8_t* block) {
	procArray[0] = *block;
	procArray[1] = *(block + 13);
	procArray[2] = *(block + 10);
	procArray[3] = *(block + 7);
	procArray[4] = *(block + 4);
	procArray[5] = *(block + 1);
	procArray[6] = *(block + 14);
	procArray[7] = *(block + 11);
	procArray[8] = *(block + 8);
	procArray[9] = *(block + 5);
	procArray[10] = *(block + 2);
	procArray[11] = *(block + 15);
	procArray[12] = *(block + 12);
	procArray[13] = *(block + 9);
	procArray[14] = *(block + 6);
	procArray[15] = *(block + 3);
	std::memcpy(block, procArray, 16);
}

void AES::MixColumns(uint8_t* block) {
	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t mult = 0; mult < 4; mult++)
			procArray[i * 4 + mult] = GFMult(constMatrix[mult][0], *(block + i * 4)) ^ GFMult(constMatrix[mult][1], *(block + i * 4 + 1)) ^ GFMult(constMatrix[mult][2], *(block + i * 4 + 2)) ^ GFMult(constMatrix[mult][3], *(block + i * 4 + 3));
	std::memcpy(block, procArray, 16);	
}

void AES::MixColumnsInv(uint8_t* block) {
	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t mult = 0; mult < 4; mult++)
			procArray[i * 4 + mult] = GFMult(constMatrixInv[mult][0], *(block + i * 4)) ^ GFMult(constMatrixInv[mult][1], *(block + i * 4 + 1)) ^ GFMult(constMatrixInv[mult][2], *(block + i * 4 + 2)) ^ GFMult(constMatrixInv[mult][3], *(block + i * 4 + 3));
	std::memcpy(block, procArray, 16);
}

uint8_t AES::GFMult(uint8_t multiplier, uint16_t multiplicant) {
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
	return (uint8_t)(multiplicant > 0xFF ? (multiplicant - 0x100) ^ 0x1B : multiplicant);
}

void AES::AddRoundKey(uint8_t* block, uint8_t keyNum) {

	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t j = 0; j < 4; j++)
			*(block + j * 4 + i) = *(block + j * 4 + i) ^ cryptoKex[keyNum][i * 4 + j];
}

void AES::ExpandKey(uint8_t* srcKey, uint8_t* dstKey, uint8_t keyNum) {
	*dstKey = SubByteSingle(*(srcKey + 7)) ^ *srcKey ^ rcon_table[keyNum];
	*(dstKey + 4) = SubByteSingle(*(srcKey + 11)) ^ *(srcKey + 4);
	*(dstKey + 8) = SubByteSingle(*(srcKey + 15)) ^ *(srcKey + 8);
	*(dstKey + 12) = SubByteSingle(*(srcKey + 3)) ^ *(srcKey + 12);
	for (uint8_t i = 1; i < 4; i++) {
		*(dstKey + i) = *(dstKey + i - 1) ^ *(srcKey + i);
		*(dstKey + i + 4) = *(dstKey + i + 3) ^ *(srcKey + i + 4);
		*(dstKey + i + 8) = *(dstKey + i + 7) ^ *(srcKey + i + 8);
		*(dstKey + i + 12) = *(dstKey + i + 11) ^ *(srcKey + i + 12);
	}
}

void AES::CalculateKeys(char* key) {
	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t j = 0; j < 4; j++)
			cryptoKex[0][j * 4 + i] = int(*(key++));
	for (uint8_t i = 1; i < 11; i++)
		ExpandKey(cryptoKex[i - 1], cryptoKex[i], i - 1);
}