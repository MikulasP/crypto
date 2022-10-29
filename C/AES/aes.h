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

	/**
	*	Egy byte kicserélése az sBox sorozatban lévő megfelelőjével.
	*
	*	@param <uint8_t>byte Kicserélésre szánt byte
	*	
	*	@returns uint8_t A megadott szám sBox megfelelője.
	*/
	uint8_t SubByteSingle(uint8_t byte);

	/// <summary>
	/// Substitute bytes in block
	/// </summary>
	/// <param name="block">The blockof data to work on</param>
	/**
	*	Blokk byte-jainak kicserélése az sBox sorozatban lévő megfelelőjükkel
	*
	*	@param <uint8_t>byte Kicserélésre szánt byte
	*/
	void SubBytes(uint8_t* block);

	/// <summary>
	/// Inverse substitute bytes in block
	/// </summary>
	/// <param name="block">The blockof data to work on</param>
	/**
	*	Blokk byte-jainak kicserélése az inverz sBox sorozatban lévő megfelelőjükkel
	*
	*	@param <uint8_t>byte Kicserélésre szánt byte
	*/
	void SubBytesInv(uint8_t* block);

	/// <summary>
	/// Shift rows left in block 
	/// </summary>
	/// <param name="block">The blockof data to work on</param>
	/**
	* 	Feldolgozás alatt lévő blokk sorainak balra eltolása
	* 
	* 	@param <uint8_t*>block		Feldolgozás alatt lévő blokk
	* 
	*/
	void ShiftRowsLeft(uint8_t* block);

	/// <summary>
	/// Shift rows right in block 
	/// </summary>
	/// <param name="block">The blockof data to work on</param>
	/**
	* 	Feldolgozás alatt lévő blokk sorainak jobbra eltolása
	* 
	* 	@param <uint8_t*>block		Feldolgozás alatt lévő blokk
	* 
	*/
	void ShiftRowsRight(uint8_t* block);

	/// <summary>
	/// Mix columns round
	/// </summary>
	/// <param name="block">The blockof data to work on</param>
	/**
	* 	Feldolgozás alatt lévő blokk oszlopainak keverése
	* 
	* 	@param <uint8_t*>block		Feldolgozás alatt lévő blokk
	* 
	*/
	void MixColumns(uint8_t* block);

	/// <summary>
	/// Inverse mix columns round
	/// </summary>
	/// <param name="block">The blockof data to work on</param>
	/**
	* 	Feldolgozás alatt lévő blokk oszlopainak inverz keverése
	* 
	* 	@param <uint8_t*>block		Feldolgozás alatt lévő blokk
	* 
	*/
	void MixColumnsInv(uint8_t* block);

	/// <summary>
	/// Galois field GF(2^8) multiplication
	/// </summary>
	/// <param name="multiplicant"> Multiplicant</param>
	/// <param name="multiplier">Multiplier (1, 2, 3, 9, 11, 13, 14)</param>
	/// <returns>The product</returns>
	uint8_t GFMult(uint8_t multiplier, uint16_t multiplicant);

	/*
	uint8_t GaloisFieldMult(uint8_t multiplier, uint8_t multiplicant);
	*/

	/// <summary>
	/// Add key to a blockof data
	/// </summary>
	/// <param name="block">The block to add key</param>
	/// <param name="keyNum">Number of the key stage</param>
	/**
	* 	Kulcs hozzáadása a feldolgozás alatt lévő blokkhoz.
	* 	
	* 	@param <uint8_t*>block		Feldolgozás alatt lévő blokk
	* 	@param <uint8_t>keyNum		A blokkhoz hozzáadandó kulcs sorszáma
	* 
	*/
	void AddRoundKey(uint8_t* block, uint8_t keyNum);

	/// <summary>
	/// 
	/// </summary>
	/// <param name="key"></param>
	/// <param name="keyNum"></param>
	/**
	* 	AES kulcs kibővítése
	* 
	* 	@param <uint8_t*>srcKey		Forrás kulcs
	* 	@param <uint8_t*>dstKey		Kibővített kulcs
	* 	@param <uint8_t>keyNum		Kibővített kulcs sorszáma
	* 
	*/
	void ExpandKey(uint8_t* srcKey, uint8_t* dstKey, uint8_t keyNum);

	/// <summary>
	/// Calculate all key stages
	/// </summary>
	/// <param name="key"></param>
	/**
	* 	AES kulcs fázisok kiszámítása és tárolása
	* 
	* 	@param	<char*>key			A titkosításhoz használt kulcs
	* 
	*/
	void CalculateKeys(char* key);

	/// <summary>
	/// Encrypt a single 16 byte long block
	/// </summary>
	/// <param name="block">Array containing the data to be encrypted</param>
	/**
	* 	Egy blokk titkosítása és felülírása.
	* 
	* 	@param	<uint8_t*>block		Titkosítandó blokk
	* 
	*/
	void EncryptBlock(uint8_t* block);

	/// <summary>
	/// Encrypt a stream of bytes from src to dst.
	/// </summary>
	/// <param name="block">Array containing the data to be encrypted</param>
	/**
	* 	Adatok titkosítása, és visszaírása a memóriába.
	* 
	* 	@param	<uint8_t*>src		A titkosítandó adatok helye a memóriában
	*	@param 	<uint8_t*>dst		A titkosított adatok helye a memóriában
	* 	@param 	<size_t>length		A titkosítandó adatok byte száma
	* 
	*/
	void EncryptStream(uint8_t* src, uint8_t* dst, size_t length);

	/// <summary>
	/// Encrypt a stream of bytes in given array. | Note: For now only works with streams divisible by 16
	/// </summary>
	/// <param name="stream"></param>
	/**
	* 	Adatok titkosítása, és felülírása a memóriában.
	* 
	*	@param 	<uint8_t*>stream	A titkosítandó adatok helye a memóriában
	* 	@param 	<size_t>length		A titkosítandó adatok byte száma
	* 
	*/
	void EncryptStreamOrigin(uint8_t* stream, size_t length);

	/**
	*	...
	* 
	*	@param	<uint8_t*>src		A titkosítandó adatok helye a memóriában
	*	@param	<size_t>length		A titkosítandó adatok byte száma
	*	@param	<size_t*>dstLength	A titkosított adatok byte száma
	* 
	*	@returns	<uint8_t*>		Pointer a titkosított adatok helyére.
	*/
	uint8_t* Encrypt(uint8_t* src, size_t length, size_t* streamLength);

	/// <summary>
	/// 
	/// </summary>
	/**
	* 	Egy blokk visszafejtése és felülírása.
	* 
	* 	@param	<uint8_t*>block		Visszafejtendő blokk.ó
	* 
	*/
	void DecryptBlock(uint8_t* block);

	/// <summary>
	/// Decrypt a previously encrypted stream of bytes from src to dst.
	/// </summary>
	/// <param name="stream"></param>
	/**
	* 	Adatok visszafejtése, és visszaírása a memóriába.
	* 
	* 	@param	<uint8_t*>src		A visszafejtendő adatok helye a memóriában
	*	@param 	<uint8_t*>dst		A visszafejtett adatok helye a memóriában
	* 	@param 	<size_t>length		A visszafejtendő adatok byte száma
	* 
	*/
	void DecryptStream(uint8_t* src, uint8_t* dst, size_t length);


	/// <summary>
	/// Decrypt a previously encrypted stream of bytes in given array. | Note: Stream length must be divisible by 16!
	/// </summary>
	/// <param name="stream"></param>
	/**
	* 	Adatok visszafejtése, és felülírása a memóriában.
	* 
	*	@param 	<uint8_t*>stream	A visszafejtendő adatok helye a memóriában
	* 	@param 	<size_t>length		A visszafejtendő adatok byte száma
	* 
	*/
	void DecryptStreamOrigin(uint8_t* stream, size_t length);

	/**
	* 
	*/
	uint8_t* Decrypt(uint8_t* src, size_t length, size_t* streamLength);
