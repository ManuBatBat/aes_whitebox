#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

//AES whitebox credit to
//  https://github.com/balena/aes-whitebox/blob/master/aes_whitebox.cc

#define Nr 14   // AES256

typedef struct{
    uint8_t     iv[16];                       // iv
    uint32_t    pad;
    uint32_t    Tyboxes[Nr-1][16][256];
    uint8_t     Xor[Nr-1][24*4][16][16];
    uint32_t    MBL[Nr-1][16][256];
    uint8_t     TboxesLast[16][256];
}AES256_WHITEBOX_DATA;

/**************************************************************************/
AES256_WHITEBOX_DATA *aes256_whitebox_get_data(char *buf,size_t len,char *iv){
/**************************************************************************/
AES256_WHITEBOX_DATA *aes;
char *p,*c;
    aes=malloc(sizeof(AES256_WHITEBOX_DATA));
    if (!aes){
        printf("Unable to alloc whitebox struct\r\n");
        return NULL;
    }
    memset(aes,0,sizeof(AES256_WHITEBOX_DATA));
    p=buf;
    while (p<buf+len){
        c=memchr(p,iv[0],len);
        if (!c || len-(c-buf)<strlen(iv)){
            printf("IV not found\r\n");
            return NULL;
        }
        if (!memcmp(c,iv,strlen(iv))) break;
        p=c+1;
        c=NULL;
    }
    if (!c){
        printf("IV not found\r\n");
        return NULL;
    }
    memcpy(aes,c,sizeof(AES256_WHITEBOX_DATA));
    return aes;
}

/**************************************************************************/
void ShiftRows(uint8_t state[16]) {
/**************************************************************************/
  const int shifts[16] = {
     0,  5, 10, 15,
     4,  9, 14,  3,
     8, 13,  2,  7,
    12,  1,  6, 11,
  };

  const uint8_t in[16] = {
    state[ 0], state[ 1], state[ 2], state[ 3],
    state[ 4], state[ 5], state[ 6], state[ 7],
    state[ 8], state[ 9], state[10], state[11],
    state[12], state[13], state[14], state[15],
  };

  for (int i = 0; i < 16; i++)
    state[i] = in[shifts[i]];
}

/**************************************************************************/
void Cipher(uint8_t in[16],AES256_WHITEBOX_DATA *aes){
/**************************************************************************/
    for (int r = 0; r < Nr-1; r++) {
        ShiftRows(in);
        for (int j = 0; j < 4; ++j) {
            uint32_t aa, bb, cc, dd;
            uint8_t n0, n1, n2, n3;

            aa = aes->Tyboxes[r][j*4 + 0][in[j*4 + 0]];
            bb = aes->Tyboxes[r][j*4 + 1][in[j*4 + 1]];
            cc = aes->Tyboxes[r][j*4 + 2][in[j*4 + 2]];
            dd = aes->Tyboxes[r][j*4 + 3][in[j*4 + 3]];

            n0 = aes->Xor[r][j*24 +  0][(aa >> 28) & 0xf][(bb >> 28) & 0xf];
            n1 = aes->Xor[r][j*24 +  1][(cc >> 28) & 0xf][(dd >> 28) & 0xf];
            n2 = aes->Xor[r][j*24 +  2][(aa >> 24) & 0xf][(bb >> 24) & 0xf];
            n3 = aes->Xor[r][j*24 +  3][(cc >> 24) & 0xf][(dd >> 24) & 0xf];
            in[j*4 + 0] = (aes->Xor[r][j*24 + 4][n0][n1] << 4) | aes->Xor[r][j*24 + 5][n2][n3];

            n0 = aes->Xor[r][j*24 +  6][(aa >> 20) & 0xf][(bb >> 20) & 0xf];
            n1 = aes->Xor[r][j*24 +  7][(cc >> 20) & 0xf][(dd >> 20) & 0xf];
            n2 = aes->Xor[r][j*24 +  8][(aa >> 16) & 0xf][(bb >> 16) & 0xf];
            n3 = aes->Xor[r][j*24 +  9][(cc >> 16) & 0xf][(dd >> 16) & 0xf];
            in[j*4 + 1] = (aes->Xor[r][j*24 + 10][n0][n1] << 4) | aes->Xor[r][j*24 + 11][n2][n3];

            n0 = aes->Xor[r][j*24 + 12][(aa >> 12) & 0xf][(bb >> 12) & 0xf];
            n1 = aes->Xor[r][j*24 + 13][(cc >> 12) & 0xf][(dd >> 12) & 0xf];
            n2 = aes->Xor[r][j*24 + 14][(aa >>  8) & 0xf][(bb >>  8) & 0xf];
            n3 = aes->Xor[r][j*24 + 15][(cc >>  8) & 0xf][(dd >>  8) & 0xf];
            in[j*4 + 2] = (aes->Xor[r][j*24 + 16][n0][n1] << 4) | aes->Xor[r][j*24 + 17][n2][n3];

            n0 = aes->Xor[r][j*24 + 18][(aa >>  4) & 0xf][(bb >>  4) & 0xf];
            n1 = aes->Xor[r][j*24 + 19][(cc >>  4) & 0xf][(dd >>  4) & 0xf];
            n2 = aes->Xor[r][j*24 + 20][(aa >>  0) & 0xf][(bb >>  0) & 0xf];
            n3 = aes->Xor[r][j*24 + 21][(cc >>  0) & 0xf][(dd >>  0) & 0xf];
            in[j*4 + 3] = (aes->Xor[r][j*24 + 22][n0][n1] << 4) | aes->Xor[r][j*24 + 23][n2][n3];

            aa = aes->MBL[r][j*4 + 0][in[j*4 + 0]];
            bb = aes->MBL[r][j*4 + 1][in[j*4 + 1]];
            cc = aes->MBL[r][j*4 + 2][in[j*4 + 2]];
            dd = aes->MBL[r][j*4 + 3][in[j*4 + 3]];

            n0 = aes->Xor[r][j*24 +  0][(aa >> 28) & 0xf][(bb >> 28) & 0xf];
            n1 = aes->Xor[r][j*24 +  1][(cc >> 28) & 0xf][(dd >> 28) & 0xf];
            n2 = aes->Xor[r][j*24 +  2][(aa >> 24) & 0xf][(bb >> 24) & 0xf];
            n3 = aes->Xor[r][j*24 +  3][(cc >> 24) & 0xf][(dd >> 24) & 0xf];
            in[j*4 + 0] = (aes->Xor[r][j*24 + 4][n0][n1] << 4) | aes->Xor[r][j*24 + 5][n2][n3];

            n0 = aes->Xor[r][j*24 +  6][(aa >> 20) & 0xf][(bb >> 20) & 0xf];
            n1 = aes->Xor[r][j*24 +  7][(cc >> 20) & 0xf][(dd >> 20) & 0xf];
            n2 = aes->Xor[r][j*24 +  8][(aa >> 16) & 0xf][(bb >> 16) & 0xf];
            n3 = aes->Xor[r][j*24 +  9][(cc >> 16) & 0xf][(dd >> 16) & 0xf];
            in[j*4 + 1] = (aes->Xor[r][j*24 + 10][n0][n1] << 4) | aes->Xor[r][j*24 + 11][n2][n3];

            n0 = aes->Xor[r][j*24 + 12][(aa >> 12) & 0xf][(bb >> 12) & 0xf];
            n1 = aes->Xor[r][j*24 + 13][(cc >> 12) & 0xf][(dd >> 12) & 0xf];
            n2 = aes->Xor[r][j*24 + 14][(aa >>  8) & 0xf][(bb >>  8) & 0xf];
            n3 = aes->Xor[r][j*24 + 15][(cc >>  8) & 0xf][(dd >>  8) & 0xf];
            in[j*4 + 2] = (aes->Xor[r][j*24 + 16][n0][n1] << 4) | aes->Xor[r][j*24 + 17][n2][n3];

            n0 = aes->Xor[r][j*24 + 18][(aa >>  4) & 0xf][(bb >>  4) & 0xf];
            n1 = aes->Xor[r][j*24 + 19][(cc >>  4) & 0xf][(dd >>  4) & 0xf];
            n2 = aes->Xor[r][j*24 + 20][(aa >>  0) & 0xf][(bb >>  0) & 0xf];
            n3 = aes->Xor[r][j*24 + 21][(cc >>  0) & 0xf][(dd >>  0) & 0xf];
            in[j*4 + 3] = (aes->Xor[r][j*24 + 22][n0][n1] << 4) | aes->Xor[r][j*24 + 23][n2][n3];
        }
    }
    ShiftRows(in);
    // Using T-boxes:
    for (int i = 0; i < 16; i++)
        in[i] = aes->TboxesLast[i][in[i]];
}

/**************************************************************************/
void aes_whitebox_encrypt_cfb(const uint8_t iv[16], const uint8_t* m, size_t len, uint8_t* c, AES256_WHITEBOX_DATA *aes){
/**************************************************************************/
uint8_t cfb_blk[16];

    for (int i = 0; i < 16; i++)
        cfb_blk[i] = iv[i];

    for (size_t i = 0; i < len; i++) {
        if ((i & 0xf) == 0)
            Cipher(cfb_blk,aes);
        cfb_blk[i & 0xf] ^= m[i];
        c[i] = cfb_blk[i & 0xf];
    }
}

/**************************************************************************/
int main(int argc, char *argv[]){
/**************************************************************************/
FILE *f;
size_t size;
char *buf;
AES256_WHITEBOX_DATA *aes;
#define M argv[3]
uint8_t *c;
size_t i;

    if (argc!=4){
        printf("AES256 CFB whitebox\r\n");
        printf("\r\n");
        printf("  usage:\r\n");
        printf("    aes_whitebox binary_file iv input\r\n");
        printf("\r\n");
        printf("       binary_file : file for recovering AES whitebox compiled data\r\n");
        printf("       iv          : initialisation vector to be searched on binary file and used as IV\r\n");
        printf("       input       : data to encrypt\r\n");
        return 1;
    }

    f=fopen(argv[1],"rb");
    if (f==NULL){
        printf("Unable to open lib file\r\n");
        return 1;
    }
    fseek(f,0,SEEK_END);
    size=ftell(f);
    fseek(f,0,SEEK_SET);
    buf=malloc(size);
    if (!buf){
        printf("Unable to alloc memory\r\n");
        fclose(f);
        return 1;
    }
    if (fread(buf,1,size,f)!=size){
        printf("Unable to read file\r\n");
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);
    aes=aes256_whitebox_get_data(buf,size,argv[2]);
    if (!aes){
        printf("Unable to get aes256 whitebox data\r\n");
        free(buf);
        return 1;
    }
    free(buf);

    c=malloc(strlen(M));
    if (!c){
        printf("Unable to allocate output buffer\r\n");
        free(aes);
        return 0;
    }

    aes_whitebox_encrypt_cfb(aes->iv,M,strlen(M),c,aes);

    for (i=0;i<strlen(M);i++){
        printf("%02X",c[i]);
    }
    printf("\r\n");

    free(aes);
    return 0;
}
