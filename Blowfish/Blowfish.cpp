
#pragma warning(disable: 4996)
//Code belongs to Bruce Schneier===================================================================
//Visit his website at https://www.schneier.com/ ==================================================

//comments written in the format:
//=================================================================================================
//xxx
//=================================================================================================
//belong to the group

#ifdef little_endian   /* Eg: Intel */
#include <dos.h>
#include <graphics.h>
#include <io.h>
#endif

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#ifdef little_endian   /* Eg: Intel */
#include <alloc.h>
#endif

#include <ctype.h>

#ifdef little_endian   /* Eg: Intel */
#include <dir.h>
#include <bios.h>
#endif

#ifdef big_endian
#include <Types.h>
#endif

#include "Blowfish.h"

#define N               16
#define noErr            0
#define DATAERROR         -1
#define KEYBYTES         8
#define subkeyfilename   "Blowfish.dat"

unsigned long P[N + 2];
unsigned long S[4][256];
FILE*         SubkeyFile;

//=================================================================================================
//This function is mostly for support.  It checks if the sub-key file is available.
//=================================================================================================
short opensubkeyfile(void) /* read only */
{
	short error;

	error = noErr;

	if((SubkeyFile = fopen(subkeyfilename,"rb")) == NULL) {
		error = DATAERROR;
	}

	return error;
}

//=================================================================================================
//
//=================================================================================================
unsigned long F(unsigned long x)
{
	unsigned short a;
	unsigned short b;
	unsigned short c;
	unsigned short d;
	unsigned long  y;

	d = x & 0x00FF;
	x >>= 8;
	c = x & 0x00FF;
	x >>= 8;
	b = x & 0x00FF;
	x >>= 8;
	a = x & 0x00FF;
	//y = ((S[0][a] + S[1][b]) ^ S[2][c]) + S[3][d];
	y = S[0][a] + S[1][b];
	y = y ^ S[2][c];
	y = y + S[3][d];

	return y;
}

//=================================================================================================
//
//=================================================================================================
void Blowfish_encipher(unsigned long *xl, unsigned long *xr)
{
	unsigned long  Xl;
	unsigned long  Xr;
	unsigned long  temp;
	short          i;

	Xl = *xl;
	Xr = *xr;

	for (i = 0; i < N; ++i) {
		Xl = Xl ^ P[i];
		Xr = F(Xl) ^ Xr;

		temp = Xl;
		Xl = Xr;
		Xr = temp;
	}

	temp = Xl;
	Xl = Xr;
	Xr = temp;

	Xr = Xr ^ P[N];
	Xl = Xl ^ P[N + 1];

	*xl = Xl;
	*xr = Xr;
}

//=================================================================================================
//
//=================================================================================================
void Blowfish_decipher(unsigned long *xl, unsigned long *xr)
{
	unsigned long  Xl;
	unsigned long  Xr;
	unsigned long  temp;
	short          i;

	Xl = *xl;
	Xr = *xr;

	for (i = N + 1; i > 1; --i) {
		Xl = Xl ^ P[i];
		Xr = F(Xl) ^ Xr;

		/* Exchange Xl and Xr */
		temp = Xl;
		Xl = Xr;
		Xr = temp;
	}

	/* Exchange Xl and Xr */
	temp = Xl;
	Xl = Xr;
	Xr = temp;

	Xr = Xr ^ P[1];
	Xl = Xl ^ P[0];

	*xl = Xl;
	*xr = Xr;
}

//=================================================================================================
//used to initialize P and S
//Note how long this process is.
//This is done to prevent adversaries from quickly changing keys.
//This function follows 7 steps described by Bruce Schneier in his paper
//1. Initialize first the P-array and then the four S-boxes, in order, with a fixed string.
//2. XOR P1 with the first 32 bits of the key, XOR P2 with the second 32-bits of the key,
//	 and so on for all bits of the key (possibly up to P14). Repeatedly cycle through the key
//	 bits until the entire P-array has been XORed with key bits.
//3. Encrypt the all-zero string with the Blowfish algorithm, using the subkeys described in
//	 steps (1) and (2).
//4. Replace P1 and P2 with the output of step (3).
//5. Encrypt the output of step (3) using the Blowfish algorithm with the modified subkeys.
//6. Replace P3 and P4 with the output of step (5).
//7. Continue the process, replacing all entries of the P- array, and then all four S-boxes
//	 in order, with the output of the continuously-changing Blowfish algorithm.
//=================================================================================================
short InitializeBlowfish(char key[], short keybytes)
{
	short          i;
	short          j;
	short          k;
	short          error;
	short          numread;
	unsigned long  data;
	unsigned long  datal;
	unsigned long  datar;


//=================================================================================================
//opens the array initialization file
//=================================================================================================
	/* First, open the file containing the array initialization data */
	error = opensubkeyfile();
	if (error == noErr) {
		for (i = 0; i < N + 2; ++i) {
//=================================================================================================
//Reads the number from the array initialization file
//=================================================================================================
			numread = fread(&data, 4, 1, SubkeyFile);
#ifdef little_endian      /* Eg: Intel   We want to process things in byte   */
			/*   order, not as rearranged in a longword          */
			data = ((data & 0xFF000000) >> 24) |
				((data & 0x00FF0000) >>  8) |
				((data & 0x0000FF00) <<  8) |
				((data & 0x000000FF) << 24);
#endif

			if (numread != 1) {
				return DATAERROR;
			} else {
//=================================================================================================
//sets the P[i] to the data read from the array initialization file
//This is step 1.
//=================================================================================================
				P[i] = data;
			}
		}

		for (i = 0; i < 4; ++i) {
			for (j = 0; j < 256; ++j) {
//=================================================================================================
//again reads from sub-key file
//=================================================================================================
				numread = fread(&data, 4, 1, SubkeyFile);

#ifdef little_endian      /* Eg: Intel   We want to process things in byte   */
				/*   order, not as rearranged in a longword          */
				data = ((data & 0xFF000000) >> 24) |
					((data & 0x00FF0000) >>  8) |
					((data & 0x0000FF00) <<  8) |
					((data & 0x000000FF) << 24);
#endif

				if (numread != 1) {
					return DATAERROR;
				} else {
//=================================================================================================
//sets S[i][j] to read number
//This is also step 1.
//=================================================================================================
					S[i][j] = data;
				}
			}
		}

		fclose(SubkeyFile);

		j = 0;
		for (i = 0; i < N + 2; ++i) {
			data = 0x00000000;
			for (k = 0; k < 4; ++k) {
//=================================================================================================
//now we create a number based on the key passed to the function
//=================================================================================================
				data = (data << 8) | key[j];
				j = j + 1;
				if (j >= keybytes) {
					j = 0;
				}
			}
//=================================================================================================
//now modify P[i] based on the created number
//This is step 2
//=================================================================================================
			P[i] = P[i] ^ data;
		}

		datal = 0x00000000;
		datar = 0x00000000;
		
//=================================================================================================
//further modify P[i] based on the encryption
//this is steps 2 through 7
//=================================================================================================
		for (i = 0; i < N + 2; i += 2) {
			Blowfish_encipher(&datal, &datar);

			P[i] = datal;
			P[i + 1] = datar;
		}
		
//=================================================================================================
//further modify S[i][j] based on encipher
//this is steps 2 through 7
//=================================================================================================
		for (i = 0; i < 4; ++i) {
			for (j = 0; j < 256; j += 2) {

				Blowfish_encipher(&datal, &datar);

				S[i][j] = datal;
				S[i][j + 1] = datar;
			}
		}
	} else {
		printf("Unable to open subkey initialization file : %d\n", error);
	}

	return error;
}

//Code written by group****************************************************************************
#include <cstring>
unsigned long make_long(char* str)
{
	unsigned long num = 0;
	int i;
	for(i = 0; i < sizeof(long); i++)
	{
		unsigned long temp = 0;
		temp = str[i];
		num += temp << (8 * i);
	}
	return num;
}

void make_string(char* str, unsigned long num)
{
	int i;
	for(i = 0; i < 32; i++)
	{
		str[i] = '\0';
		str[i] |= num;
		num = num >> 8;
	}

}

char parse_input()
{
	char input[100];
	scanf("%s", input);
	if(!strcmp(input, "ENC"))
		return 'e';
	if(!strcmp(input, "DEC"))
		return 'd';
	if(!strcmp(input, "SEND"))
		return 's';
	if(!strcmp(input, "QUIT"))
		return 'q';
	return 'x';
}

int main()
{
	char keystuff[8] = {'b','l','o','w','f','i','s','h'};
	char input[129];
	char choice = 'q';
	int i;
	unsigned long right = 500;
	unsigned long left = 500;

	InitializeBlowfish(keystuff,8);

	printf("Welcome to the Blowfish encryption system.\n");
	do
	{
		for(i = 0; i < 128; i++)
			input[i] = '\0';

		printf("Please enter a choice:\n");
		printf("ENC - encrypt a message\n");
		printf("DEC - decrypt a cipher test\n");
		printf("SEND - encrypt and then decrypt a message\n");
		printf("QUIT - exit system\n");
		choice = parse_input();
		switch(choice)
		{
		case 'e':
			printf("Please enter a message to encrypt: ");
			scanf("%s", input);
			left = make_long(input);
			right = make_long(input + (sizeof(long)));
			Blowfish_encipher(&left, &right);
			printf("\nYour message encrypts to the number: \n%010ul %010ul\n", left, right);
			break;
		case 'd':
			printf("Please enter a cipher text to decrypt: ");
			scanf("%ul", left);
			scanf("%ul", right);
			Blowfish_decipher(&left, &right);
			make_string(input, left);
			make_string(input + sizeof(long), right);
			input[64] = '\0';
			printf("\nYour cipher text decrypts to: \n%s\n", input);
			break;
		case 's':
			printf("Please enter a message to encrypt and then decrypt: ");
			scanf("%s", input);
			left = make_long(input);
			right = make_long(input + (sizeof(long)));
			Blowfish_encipher(&left, &right);
			printf("\nYour message encrypts to the number: \n%010ul %010ul\n", left, right);
			for(i = 0; i < 128; i++)
				input[i] = '\0';
			Blowfish_decipher(&left, &right);
			make_string(input, left);
			make_string(input + sizeof(long), right);
			input[64] = '\0';
			printf("Your cipher text decrypts to: \n%s\n\n", input);
			break;
		case 'x':
			printf("Error reading input\n");
			break;
		}
	}while(choice != 'q');
	return 0;
}