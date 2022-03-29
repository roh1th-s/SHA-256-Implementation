/**
 * Author:    Rohith Suju
 * Created:   09.03.2022
 * 
 * A simple sha256 implementation
 * 
 * References:
 *  - https://qvault.io/cryptography/how-sha-2-works-step-by-step-sha-256/ 
 *  - https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values#aHashing
**/

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>

typedef unsigned char uint8_t;       // 1 byte
typedef unsigned int uint32_t;       // 4 bytes
typedef unsigned long long uint64_t; // 8 bytes

char* toHex(uint32_t bin) {
    char* hex = (char *)malloc(sizeof(char) * 9);
    memset(hex, 0, sizeof(char) * 9);
    sprintf(hex, "%08x", bin);
    return hex;
}

uint32_t leftRotate(uint32_t x, uint32_t c)
{
    return (x << c) | (x >> (32 - c));
}

uint32_t rightRotate(uint32_t x, uint32_t c)
{
    return (x >> c) | (x << (32 - c));
}

// Assumes little endian
void printBits(size_t const size, const void *const ptr)
{
    unsigned char *b = (unsigned char *)ptr;
    unsigned char byte;
    int i, j;

    for (i = size - 1; i >= 0; i--)
    {
        for (j = 7; j >= 0; j--)
        {
            // moving jth bit to the rightmost and seeing if it is a 1 or 0;
            //  thus, byte will have a value of 1 or 0
            byte = (b[i] >> j) & 1;
            printf("%u", byte);
        }
    }
}

void printPreProcessed(uint8_t *pre_processed, int n)
{
    for (size_t i = 0; i < n; i += 1)
    {
        if (i % 8 == 0)
        {
            printf("\n");
        }

        //printf("%s  ", toHex((uint32_t)*(pre_processed + i)));
        printBits(sizeof(uint8_t), (pre_processed + i));
        printf("\t");
    }
}

void print32BitWordArray(uint32_t *word_array, int n)
{
    for (size_t i = 0; i < n; i += 1)
    {
        if (i % 2 == 0)
        {
            printf("\n");
        }

        //printf("%s\t", toHex(word_array[i]));
        printBits(sizeof(uint32_t), (word_array + i));
        printf("\t");
    }
}

void intToByteArray(uint64_t n, uint8_t *array)
{
    for (int i = 7; i >= 0; i -= 1)
    {
        // first shift right to move the bits of the current byte to the
        // extreme right. Then mask off the bits we don't want.
        array[i] = (n >> (i * 8)) & 0xFF;
    }
}

void convertChunkTo32BitWordArray(uint8_t *pre_processed, int size_of_preprocessed, int chunk, uint32_t *word_array)
{   
    size_t startBytes = chunk * 64;
    for (size_t i = startBytes; i < size_of_preprocessed + startBytes; i += 4)
    {
        uint32_t word = 0;
        for (int j = 0; j < 4; j += 1)
        {
            word = word | (((uint32_t)pre_processed[i + j]) << ((3 - j) * 8));
        }
        word_array[(i - startBytes) / 4] = word;
    }
}

char *sha_256(char *input, size_t n)
{
    // (n - 1) -> Length of input string (removing the null char)
    // 1 -> Minimum bytes of padded 0s (along with the seperator '1')
    // 8 -> Bytes to store size of input string.
    // => ceil(n + 8 / 64) = no of chunks

    const unsigned int noOfChunks = (unsigned int)ceil((double)(n + 8) / 64);
    printf("No of chunks: %u\n", noOfChunks);

    // pre-processed must have "multiple of 64" bytes of data;
    int noOfBytes = noOfChunks * 64;
    uint8_t *pre_processed = (uint8_t *)calloc((size_t)noOfBytes, sizeof(uint8_t));



    for (size_t i = 0; i < n - 1; i += 1)
    {
        pre_processed[i] = (uint8_t)input[i];
    }
    pre_processed[n - 1] = 0x80; // 10000000

    // 8 byte size of input
    uint8_t byteArrayOfInputSize[8];

    intToByteArray((size_t)(n - 1) * 8, byteArrayOfInputSize);

    for (int i = noOfBytes - 1; i >= noOfBytes - 8; i -= 1)
    {   
        pre_processed[i] = byteArrayOfInputSize[noOfBytes - 1 - i];
    }

    // Initialize hash values
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    // Initialize array of round constants
    uint32_t ROUND_CONSTANTS[] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

    // chunk loop
    for (size_t chunk = 0; chunk < noOfChunks; chunk++)
    {
        uint32_t words[64] = {0};
        convertChunkTo32BitWordArray(pre_processed, 64, chunk, words);

        for (int i = 16; i < 64; i += 1)
        {
            uint32_t s0 = rightRotate(words[i - 15], 7) ^ rightRotate(words[i - 15], 18) ^ (words[i - 15] >> 3);

            uint32_t s1 = rightRotate(words[i - 2], 17) ^ rightRotate(words[i - 2], 19) ^ (words[i - 2] >> 10);

            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }

        // initial working varibles
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        // compression loop
        for (int i = 0; i < 64; i++)
        {
            uint32_t s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t t1 = h + s1 + ch + ROUND_CONSTANTS[i] + words[i];

            uint32_t s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        //update hash values
        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
        h5 = h5 + f;
        h6 = h6 + g;
        h7 = h7 + h;
    }

    char *digest = (char *)malloc(sizeof(char) * 64);
    memset(digest, 0, sizeof(char) * 64);

    strcat(digest, toHex(h0));
    strcat(digest, toHex(h1));
    strcat(digest, toHex(h2));
    strcat(digest, toHex(h3));
    strcat(digest, toHex(h4));
    strcat(digest, toHex(h5));
    strcat(digest, toHex(h6));
    strcat(digest, toHex(h7));

    return digest;
}

int main(int const argc, char *argv[])
{   
    if (argc < 1)
        return 0;

    size_t strsize = 0;
    for (int i=1; i<argc; i++) {
        strsize += strlen(argv[i]);
        if (argc > i+1)
            strsize++;
    }

    strsize++; //null terminator

    char *input;
    input = malloc(strsize);
    input[0] = '\0';

    for (int i=1; i<argc; i++) {
        strcat(input, argv[i]);
        if (argc > i+1)
            strcat(input, " ");
    }

    printf("\nInput: %s\n", input);

    char *output = sha_256(input, strlen(input) + 1);
    printf("\nSHA-265 Digest : %s\n", output);
    
    return 0;
}