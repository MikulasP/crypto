/*

	Code by MikulasP 2022
	WEB:		https://mikulasp.net
	GitHub:		https://github.com/MikulasP

	Rev.:		0.1 Beta (July 5, 2022)
*/
/*
MIT License

Copyright (c) 2022 Mikulas Peter

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define AES_MAX_BUFFER_SIZE    8 * ( 1000 /* 1 kB */ )    //Max buffer size on heap in megabytes -!!- MUST BE MULTIPLE OF 16 bytes -!!-
/*
* 
*	Note: This size only restricts single buffers, NOT the whole program buffer size.
* 
*/

/**
*	AES dataset to pass and receive data while processing.
*/
typedef struct AES_DATASET {
	char* inputFileName;			///< Input file's name (file to process)
	char* outputFileName;			///< Output file's name (processed file)
	uint8_t* srcStream;				///< Pointer to source stream (stream to process)
	uint8_t* dstStream;				///< Pointer to destination stream (processed stream)
	size_t streamLen;				///< Source stream length (only used with stream operations)
	size_t progress;				///< Progress feedback (nuber of bytes processed) Can be read out to get progress with multithreaded operations
} AES_DATASET;

/**
* 	Encrypt a single 16 byte long block*
*
* 	@param	<uint8_t*>block		Array containing the data to be encrypted
*
*/
void EncryptBlock(uint8_t* block);

/**
* 	Encrypt stream of bytes
* 	@param	<uint8_t*>src			Source stream
*	@param <uint8_t*>dst			Destination stream
* 	@param <size_t>length			Source length
*
*/
void EncryptStream(uint8_t* src, uint8_t* dst, size_t length);

/**
* 	Encrypt stream at original position
*
*	@param <uint8_t*>stream			Source stream
* 	@param <size_t>length			Source length
*
*/
void EncryptStreamOrigin(uint8_t* stream, size_t length);

/**
*	Encrypt and pad a stream of bytes
*
*	@param <uint8_t*>src			Source stream
*	@param <size_t>length			Source length
*	@param <size_t*>dstLength		Finished stream length
*	@param <bool>attachPadding		Attach padding to last block
*
*	@returns	<uint8_t*>		Pointer to encrypted data
*/
uint8_t* Encrypt(uint8_t* src, size_t length, size_t* streamLength, bool attachPadding);

/**
*	Encrypt and save file
*
*	@param <AES_DATASET*>dataset	Pointer to AES_DATASET struct
*
*	@returns <int>					Exit code (See documentation page X) (later)
*/
//int EncryptFileToFile(char* inputFileName, char* outputFileName, size_t* encryptedSizePtr, size_t* fullSizePtr);
int EncryptFileToFile(AES_DATASET* dataset);

/**
*	Encrypr file tostream
*
*	@param	<char*>inputFileName	Source file name
*	@param	<uint8_t*>stream		Encrypted file stream
*	@param	<size_t*>				Length of the encrypted stream
*
*	@returns <int>					Exit code (See documentation page X) (later)
*/
//int EncryptFileToStream(char* inputFileName, uint8_t* stream, size_t* streamLength);

/**
* 	Decrypt a single 16 byte long block*
*
* 	@param	<uint8_t*>block			Array containing the data to be decrypted
*
*/
void DecryptBlock(uint8_t* block);

/**
* 	Decrypt stream of bytes
*
* 	@param	<uint8_t*>src			Source stream
*	@param <uint8_t*>dst			Destination stream
* 	@param <size_t>length			Source length
*
*/
void DecryptStream(uint8_t* src, uint8_t* dst, size_t length);

/**
* 	Decrypt stream at original position
*
*	@param <uint8_t*>stream			Source stream
* 	@param <size_t>length			Source length
*
*/
void DecryptStreamOrigin(uint8_t* stream, size_t length);

/**
*	Decrypt and pad a stream of bytes
*
*	@param <uint8_t*>src			Source stream
*	@param <size_t>length			Source length
*	@param <size_t*>streamength		Finished stream length
*	@param <bool>removePadding		Remove padding from the last block
*
*	@returns	<uint8_t*>			Pointer to decrypted data
*/
uint8_t* Decrypt(uint8_t* src, size_t length, size_t* streamLength, bool removePadding);

/**
*/
//int DecryptFileToFile(char* inputFileName, char* outputFileName, size_t* decryptedSizePtr, size_t* fullSizePtr);
int DecryptFileToFile(AES_DATASET* dataset);

/**
*	Substitute a single byte
*
*	@param <uint8_t>byte The byte to replace*
* 
*	@returns uint8_t Corresponding byte according to sBox
*/
uint8_t SubByteSingle(uint8_t byte);

/**
*	Substitute bytes in block
*
*	@param <uint8_t>byte The block of data to work on
*/
void SubBytes(uint8_t* block);

/**
*	Inverse substitute bytes in block
*
*	@param <uint8_t>byte The blockof data to work on
*/
void SubBytesInv(uint8_t* block);

/**
* 	Shift rows left in block
*
* 	@param <uint8_t*>block		The block of data to work on
*
*/
void ShiftRowsLeft(uint8_t* block);

/**
* 	Shift rows right in block
*
* 	@param <uint8_t*>block		The block of data to work on
*
*/
void ShiftRowsRight(uint8_t* block);

/**
* 	Mix columns round
*
* 	@param <uint8_t*>block		The block of data to work on
*
*/
void MixColumns(uint8_t* block);

/**
* 	Inverse mix columns round
*
* 	@param <uint8_t*>block		The blockof data to work on
*
*/
void MixColumnsInv(uint8_t* block);

/**
	Galois field GF(2^8) multiplication

	@param <uint8_t>Multiplicant
	@param <uint8_t>Multiplier
*/
uint8_t GFMult(uint8_t multiplier, uint16_t multiplicant);

/**
* 	Add key to a blockof data
*
* 	@param <uint8_t*>block		The block to add key
* 	@param <uint8_t>keyNum		Number of the key stage
*
*/
void AddRoundKey(uint8_t* block, uint8_t keyNum);

/**
* 	Expand AES keys
*
* 	@param <uint8_t*>srcKey		Source key
* 	@param <uint8_t*>dstKey		Destination key
* 	@param <uint8_t>keyNum		Expanded key’s number
*
*/
void ExpandKey(uint8_t* srcKey, uint8_t* dstKey, uint8_t keyNum);

/**
* 	Calculate aes key stages (Input must be 16 bytes long!)
*
* 	@param	<char*>key			AES Secret key
*
*/
void CalculateKeys(char* key);

/**
*	Get a file's size int bytes
* 
*	@param <FILE*>file			Input file
* 
*	@returns <size_t>			The input file's size in byzes
*/
size_t GetFileSizeBytes(FILE* file);

/**
*	Set key from a string given by a user (most likely)
* 
*	@param <char*>str				String containing the key
*/
void SetKeyString(char* str);

