#include "aes_config.h"
#include "aes.h"

//
void AES::Init(char* key) {
	CalculateKeys(key);
}

//
void AES::ChangeSecretKey(char* key) {
	CalculateKeys(key);
}

//
void AES::EncryptBlock(uint8_t* block) {
	if (block == NULL)		return;

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

//
void AES::EncryptStreamOrigin(uint8_t* stream, size_t length) {
	if (stream == NULL)		return;
	size_t blcks = length / 16;
	for (size_t i = 0; i < blcks; i++)
		EncryptBlock(stream + i * 16);
}

//
void AES::EncryptStream(uint8_t* src, uint8_t* dst, size_t length) {
	if (src == NULL || dst == NULL)		return;
	memcpy(dst, src, length);
	EncryptStreamOrigin(dst, length);
}

//
uint8_t* AES::Encrypt(uint8_t* src, size_t length, size_t* streamLength, bool attachPadding) {
	if (src == NULL || length < 1)	return NULL;		//Define error	->	NULL src or length

	*streamLength = length + (attachPadding ? ((length & 0x0F) == 0 ? 0x10 : 16 - (length & 0x0F)) : length);

	uint8_t* dstStream = (uint8_t*)malloc((*streamLength) * sizeof(uint8_t));
	if (dstStream == NULL)	return dstStream;			//Define error	->	Mem. allocation falied

	memcpy(dstStream, src, length);

	//Padding the data with #PKCS7
	if (attachPadding)
		for (size_t i = (*streamLength) - 1; i >= length; i--)
			dstStream[i] = ((length & 0x0F) == 0 ? 0x10 : 16 - (length & 0x0F));

	EncryptStreamOrigin(dstStream, *streamLength);

	return dstStream;
}

//
int AES::EncryptFileToFile(char* inputFileName, char* outputFileName) {

	if (inputFileName == NULL || outputFileName == NULL)	return 0x0A;

	FILE* inputFile;
	fopen_s(&inputFile, inputFileName, "rb");
	if (inputFile == NULL)		return 0x01;		//Error while opening source file

	//Input file's length in bytes
	size_t streamLen = GetFileSizeBytes(inputFile);
	if (streamLen < 1)			return 0x02;

	//Create output file
	FILE* outputFile;
	fopen_s(&outputFile, outputFileName, "wb");
	if (outputFile == NULL)		return 0x03;		//Error creating output file

	//The maximum ammount of data (bytes) to work on at once
	size_t dataChunkSize = (streamLen > AES_MAX_BUFFER_SIZE ? AES_MAX_BUFFER_SIZE : streamLen);

	size_t encryptedChunkSize = 0;

	//Encrypting without padding
	while (streamLen > dataChunkSize) {

		//Store data from file
		uint8_t* rawData = (uint8_t*)malloc(dataChunkSize * sizeof(uint8_t));

		//Read data from file into buffer
		fread(rawData, sizeof(uint8_t), dataChunkSize, inputFile);

		uint8_t* encryptedData = Encrypt(rawData, dataChunkSize, &encryptedChunkSize, false);

		//Don't need this anymore
		free(rawData);

		fwrite(encryptedData, sizeof(uint8_t), dataChunkSize, outputFile);
		fflush(outputFile);

		encryptedChunkSize = 0;

		streamLen -= dataChunkSize;

		//Free up memory
		free(encryptedData);
	}

	//Last round with padding
	uint8_t* rawData = (uint8_t*)malloc(streamLen * sizeof(uint8_t));

	//Read data from file into buffer
	fread_s(rawData, streamLen * sizeof(uint8_t), sizeof(uint8_t), streamLen, inputFile);

	uint8_t* encryptedData = Encrypt(rawData, streamLen, &encryptedChunkSize, true);

	fwrite(encryptedData, sizeof(uint8_t), encryptedChunkSize, outputFile);
	fflush(outputFile);

	free(rawData);
	free(encryptedData);

	//Close files
	fclose(outputFile);
	fclose(inputFile);

	return 0x00;
}

//
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

//
void AES::DecryptStream(uint8_t* src, uint8_t* dst, size_t length) {
	memcpy(dst, src, length);
	DecryptStreamOrigin(dst, length);
}

//
void AES::DecryptStreamOrigin(uint8_t* stream, size_t length) {
	size_t blcks = length / 16;
	for (size_t i = 0; i < blcks; i++)
		DecryptBlock(stream + i * 16);
}

//
uint8_t* AES::Decrypt(uint8_t* src, size_t length, size_t* streamLength, bool removePadding) {
	if (src == NULL || length < 1) return NULL;		//Define error	->	NULL src or length

	if ((length & 0x0F) != 0) { printf("\nAES: Bad stream size!\n"); return NULL; }			//Define error	->	Bad stream size


	uint8_t* dstStream = (uint8_t*)malloc(length);
	if (dstStream == NULL)	return dstStream;		//Define error	->	Mem. allocation falied

	memcpy(dstStream, src, length);

	DecryptStreamOrigin(dstStream, length);

	*streamLength = length - (removePadding ? (dstStream[length - 1] == 0x10 ? 0x10 : dstStream[length - 1]) : 0);

	return dstStream;
}

size_t AES::DecryptFileToFile(char* inputFileName, char* outputFileName) {

	if (inputFileName == NULL || outputFileName == NULL)	return 0x0A;

	FILE* inputFile;
	fopen_s(&inputFile, inputFileName, "rb");
	if (inputFile == NULL)		return 0x01;			//Error while opening source file


	//
	size_t streamLen =  GetFileSizeBytes(inputFile);

	if (streamLen < 1)		return 0x02;			//Empty input file
	if ((streamLen & 0x0F) != 0x00)	return 0x03;	//Bad file size

	//Create output file
	FILE* outputFile;
	fopen_s(&outputFile, outputFileName, "wb");
	if (outputFile == NULL)		return 0x04;			//Error creating output file

	//The maximum ammount of data (bytes) to work on at once
	size_t dataChunkSize = (streamLen > AES_MAX_BUFFER_SIZE ? AES_MAX_BUFFER_SIZE : streamLen);

	size_t encryptedChunkSize = 0;

	//Encrypting without padding
	while (streamLen > dataChunkSize) {

		//Store data from file
		uint8_t* rawData = (uint8_t*)malloc(dataChunkSize * sizeof(uint8_t));

		//Read data from file into buffer
		fread(rawData, sizeof(uint8_t), dataChunkSize, inputFile);

		uint8_t* decryptedData = Decrypt(rawData, dataChunkSize, &encryptedChunkSize, false);

		fwrite(decryptedData, sizeof(uint8_t), dataChunkSize, outputFile);
		fflush(outputFile);

		//Updating tracker
		//progress += encryptedChunkSize;
		encryptedChunkSize = 0;

		streamLen -= dataChunkSize;

		//Free up memory
		free(decryptedData);
		free(rawData);
	}

	//Last round with padding
	uint8_t* rawData = (uint8_t*)malloc(streamLen * sizeof(uint8_t));

	//Read data from file into buffer
	fread_s(rawData, streamLen * sizeof(uint8_t), sizeof(uint8_t), streamLen, inputFile);

	uint8_t* decryptedData = Decrypt(rawData, streamLen, &encryptedChunkSize, true);

	fwrite(decryptedData, sizeof(uint8_t), encryptedChunkSize, outputFile);
	fflush(outputFile);

	free(rawData);
	free(decryptedData);

	//Close files
	fclose(outputFile);
	fclose(inputFile);

	return 0x00;
}

//
uint8_t AES::SubByteSingle(uint8_t byte) {
	return sBox[byte >> 4][byte & 0x0F];
}

//
void AES::SubBytes(uint8_t* block) {
	for (uint8_t i = 0; i < 16; i++)
		block[i] = sBox[block[i] >> 4][block[i] & 0x0F];
}

//
void AES::SubBytesInv(uint8_t* block) {
	for (uint8_t i = 0; i < 16; i++)
		block[i] = sBoxInv[block[i] >> 4][block[i] & 0x0F];
}

//
void AES::ShiftRowsLeft(uint8_t* block) {
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

//
void AES::ShiftRowsRight(uint8_t* block) {
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

//
void AES::MixColumns(uint8_t* block) {
	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t mult = 0; mult < 4; mult++)
			procArray[i * 4 + mult] = GFMult(constMatrix[mult][0], block[i * 4]) ^ GFMult(constMatrix[mult][1], block[i * 4 + 1]) ^ GFMult(constMatrix[mult][2], block[i * 4 + 2]) ^ GFMult(constMatrix[mult][3], block[i * 4 + 3]);
	memcpy(block, procArray, 16);
}

//
void AES::MixColumnsInv(uint8_t* block) {
	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t mult = 0; mult < 4; mult++)
			procArray[i * 4 + mult] = GFMult(constMatrixInv[mult][0], block[i * 4]) ^ GFMult(constMatrixInv[mult][1], block[i * 4 + 1]) ^ GFMult(constMatrixInv[mult][2], block[i * 4 + 2]) ^ GFMult(constMatrixInv[mult][3], block[i * 4 + 3]);
	memcpy(block, procArray, 16);
}

//
uint8_t AES::GFMult(uint8_t multiplier, uint16_t multiplicant) {
	switch (multiplier)
	{
	case 1:
		return (uint8_t)multiplicant;
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
		return 0;
	}
	return (uint8_t)(multiplicant >= GF_MULT_OVERFLOW ? (multiplicant - GF_MULT_OVERFLOW) ^ 0x1B : multiplicant);
}

//
void AES::AddRoundKey(uint8_t* block, uint8_t keyNum) {

	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t j = 0; j < 4; j++)
			block[j * 4 + i] = block[j * 4 + i] ^ cryptoKex[keyNum][i * 4 + j];
}

//
void AES::ExpandKey(uint8_t* srcKey, uint8_t* dstKey, uint8_t keyNum) {
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

//
void AES::CalculateKeys(char* key) {

	char keyArr[16] = { 0 };

	char i;
	for (i = 0; i < 16 && key[i] != '\0'; i++)
		keyArr[i] = key[i];

	for (; i < 16; i++)
		keyArr[i] = 0;

	for (uint8_t i = 0; i < 4; i++)
		for (uint8_t j = 0; j < 4; j++)
			cryptoKex[0][j * 4 + i] = keyArr[i * 4 + j];

	for (uint8_t i = 1; i < 11; i++)
		ExpandKey(cryptoKex[i - 1], cryptoKex[i], i - 1);
}

//
size_t AES::GetFileSizeBytes(FILE* file) {
	if (!file)
		return 0;
	size_t filePointerPos = (size_t)ftell(file);
	fseek(file, 0, SEEK_END);
	size_t fileSize = ftell(file);
	fseek(file, filePointerPos, SEEK_SET);
	return fileSize;
}

size_t AES::GetFileSizeBytes(char* fileName) {
	FILE* targetFile;
	fopen_s(&targetFile, (const char*)fileName, "r");
	if (!targetFile)
		return 0;
	fseek(targetFile, 0, SEEK_END);
	size_t fileSize = ftell(targetFile);
	fclose(targetFile);
	return fileSize;
}
