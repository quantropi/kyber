
//
//  PQCgenKAT_kem.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "kem.h"

#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);
//added for QA test header output file
void qa_hex_to_str(unsigned char *hex, int hex_len, unsigned char *str);
int validate(char *hex);
int valueOf(char symbol);
char* hexToAscii(char hex[]);
//end

int
main()
{
    char                fn_req[32], fn_rsp[32];
    FILE                *fp_req, *fp_rsp;
    unsigned char       seed[48];
    unsigned char       entropy_input[48];
    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
    int                 count;
    int                 done;
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;

    //added for QA test header output file
    uint8_t             *str;
    char                fn_rsp_qa[32];
    FILE                *fp_rsp_qa;
    //end

    // Create the REQUEST file
    sprintf(fn_req, "PQCkemKAT_%d.req", CRYPTO_SECRETKEYBYTES);
    if ( (fp_req = fopen(fn_req, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
    sprintf(fn_rsp, "PQCkemKAT_%d.rsp", CRYPTO_SECRETKEYBYTES);
    if ( (fp_rsp = fopen(fn_rsp, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }
    //added for QA test header output file
    sprintf(fn_rsp_qa, "PQCkemKAT_%d_qa.h", ALGO);
    if ( (fp_rsp_qa = fopen(fn_rsp_qa, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_rsp_qa);
        return KAT_FILE_OPEN_ERROR;
    }
    //end

    for (int i=0; i<48; i++)
        entropy_input[i] = i;

    randombytes_init(entropy_input, NULL, 256);
    for (int i=0; i<100; i++) {
        fprintf(fp_req, "count = %d\n", i);
        randombytes(seed, 48);
        fprintBstr(fp_req, "seed = ", seed, 48);
        fprintf(fp_req, "pk =\n");
        fprintf(fp_req, "sk =\n");
        fprintf(fp_req, "ct =\n");
        fprintf(fp_req, "ss =\n\n");
    }
    fclose(fp_req);

    //Create the RESPONSE file based on what's in the REQUEST file
    if ( (fp_req = fopen(fn_req, "r")) == NULL ) {
        printf("Couldn't open <%s> for read\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }

    fprintf(fp_rsp, "# %s\n\n", CRYPTO_ALGNAME);
    //added for QA test header output file
    fprintf(fp_rsp_qa, "testVectorRec test_vector[] ={\n\n");
    //end
    done = 0;
    do {
        if ( FindMarker(fp_req, "count = ") )
            fscanf(fp_req, "%d", &count);
        else {
            done = 1;
            break;
        }
        fprintf(fp_rsp, "count = %d\n", count);

        if ( !ReadHex(fp_req, seed, 48, "seed = ") ) {
            printf("ERROR: unable to read 'seed' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "seed = ", seed, 48);

        randombytes_init(seed, NULL, 256);

        // Generate the public/private keypair
        if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
            printf("crypto_kem_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
        fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);

        if ( (ret_val = crypto_kem_enc(ct, ss, pk)) != 0) {
            printf("crypto_kem_enc returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintBstr(fp_rsp, "ct = ", ct, CRYPTO_CIPHERTEXTBYTES);
        fprintBstr(fp_rsp, "ss = ", ss, CRYPTO_BYTES);

        fprintf(fp_rsp, "\n");

        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) {
            printf("crypto_kem_dec returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }

        if ( memcmp(ss, ss1, CRYPTO_BYTES) ) {
            printf("crypto_kem_dec returned bad 'ss' value\n");
            return KAT_CRYPTO_FAILURE;
        }

       //added for QA test header output file
        fprintf(fp_rsp_qa, "{.count = %d,\n", count+1);
        fprintf(fp_rsp_qa, ".algorithmID = LEVEL%d,\n", ALGO);

        str = malloc(48*8); 
		qa_hex_to_str(seed,48,str);
        fprintf(fp_rsp_qa, ".seed = (unsigned char *) \"%s\",\n", str);
        free(str);

        fprintf(fp_rsp_qa, ".seedLen = 48,\n");

        fprintf(fp_rsp_qa, ".api_rv = MASQ_SUCCESS\n");
        fprintf(fp_rsp_qa, "},\n");
        //end

    } while ( !done );

    fprintf(fp_rsp_qa, "\n};\n");

    fclose(fp_req);
    fclose(fp_rsp);
    fclose(fp_rsp_qa);

    return KAT_SUCCESS;
}



//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
FindMarker(FILE *infile, const char *marker)
{
	char	line[MAX_MARKER_LEN];
	int		i, len;
	int curr_line;

	len = (int)strlen(marker);
	if ( len > MAX_MARKER_LEN-1 )
		len = MAX_MARKER_LEN-1;

	for ( i=0; i<len; i++ )
	  {
	    curr_line = fgetc(infile);
	    line[i] = curr_line;
	    if (curr_line == EOF )
	      return 0;
	  }
	line[len] = '\0';

	while ( 1 ) {
		if ( !strncmp(line, marker, len) )
			return 1;

		for ( i=0; i<len-1; i++ )
			line[i] = line[i+1];
		curr_line = fgetc(infile);
		line[len-1] = curr_line;
		if (curr_line == EOF )
		    return 0;
		line[len] = '\0';
	}

	// shouldn't get here
	return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
	int			i, ch, started;
	unsigned char	ich;

	if ( Length == 0 ) {
		A[0] = 0x00;
		return 1;
	}
	memset(A, 0x00, Length);
	started = 0;
	if ( FindMarker(infile, str) )
		while ( (ch = fgetc(infile)) != EOF ) {
			if ( !isxdigit(ch) ) {
				if ( !started ) {
					if ( ch == '\n' )
						break;
					else
						continue;
				}
				else
					break;
			}
			started = 1;
			if ( (ch >= '0') && (ch <= '9') )
				ich = ch - '0';
			else if ( (ch >= 'A') && (ch <= 'F') )
				ich = ch - 'A' + 10;
			else if ( (ch >= 'a') && (ch <= 'f') )
				ich = ch - 'a' + 10;
            else // shouldn't ever get here
                ich = 0;

			for ( i=0; i<Length-1; i++ )
				A[i] = (A[i] << 4) | (A[i+1] >> 4);
			A[Length-1] = (A[Length-1] << 4) | ich;
		}
	else
		return 0;

	return 1;
}

void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
	unsigned long long  i;

	fprintf(fp, "%s", S);

	for ( i=0; i<L; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}

/**************************************************************************************************
* Push hex data into printable string char
**************************************************************************************************/
void qa_hex_to_str(unsigned char *hex, int hex_len, unsigned char *str) {
	sprintf(str,"");
    for (int i=0; i < hex_len; i++) {
     sprintf(str,"%s%02X", str, (hex[i]&0xff));
    }
}

//Soure code: https://github.com/ProgrammingSimpleSteps/c-examples/blob/main/number-systems/hex-to-ascii/hex-to-ascii.c
char* hexToAscii(char hex[])
{
    int hexLength = strlen(hex);
	char* text = NULL;
    
	if(hexLength > 0)
	{
		int symbolCount;
		int oddHexCount = hexLength % 2 == 1;
		if(oddHexCount)
			symbolCount = (hexLength / 2) + 1;
		else
			symbolCount = hexLength / 2;
		
		text = malloc(symbolCount + 1);
		
		int lastIndex = hexLength - 1;
		for(int i = lastIndex; i >= 0; --i)
		{
			if(((lastIndex - i) % 2 != 0))
			{
				int dec = 16 * valueOf(hex[i]) + valueOf(hex[i+1]);
				if(oddHexCount)
					text[i/2+1] = dec;
				else
					text[i/2] = dec;
			}
			else if(i == 0)
			{
				int dec = valueOf(hex[0]);
				text[0] = dec;
			}
		}
		text[symbolCount] = '\n';
    }

    printf("text %s", text);
    return text;
}
  
int valueOf(char symbol)
{
	switch(symbol)
	{
		case '0': return 0;
		case '1': return 1;
		case '2': return 2;
		case '3': return 3;
		case '4': return 4;
		case '5': return 5;
		case '6': return 6;
		case '7': return 7;
		case '8': return 8;
		case '9': return 9;
		case 'A':
		case 'a': return 10;
		case 'B':
		case 'b': return 11;
		case 'C':
		case 'c': return 12;
		case 'D':
		case 'd': return 13;
		case 'E':
		case 'e': return 14;
		case 'F':
		case 'f': return 15;
		default:
		{
			printf("Cannot decode that symbol: %c", symbol);
			return -1;
		}
	}
}

int validate(char* hex)
{
	printf("Validating: ");
	while(*hex)
	{
		printf("%c", *hex);
		switch(*hex)
		{
			case '0': 
			case '1': 
			case '2': 
			case '3': 
			case '4': 
			case '5': 
			case '6': 
			case '7': 
			case '8': 
			case '9': 
			case 'A':
			case 'a': 
			case 'B':
			case 'b': 
			case 'C':
			case 'c': 
			case 'D':
			case 'd': 
			case 'E':
			case 'e': 
			case 'F':
			case 'f': break;
			default:
			{
				printf(" ..Failed.\n");
				return 0;
			}
		}
		++hex;
	}
	printf(" ..OK.\n");
	return 1;
}
