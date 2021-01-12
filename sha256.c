#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "sha256.h"

// Operations
#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define SHL(x, n) ((x) >> (n))
#define SHR(x, n) ((x) >> (n))

// Functions
#define CH(x,y,z) ((x) & (y)) ^ (~(x) & (z))
#define MAJ(x, y ,z) (((x) & (y))^((x) & (z))^((y) & (z)))

#define B_SIGMA_0(x) ((ROTR((x), 2)) ^ (ROTR((x), 13)) ^ (ROTR((x),22)))
#define B_SIGMA_1(x) ((ROTR((x), 6)) ^ (ROTR((x), 11)) ^ (ROTR((x),25)))

#define SIGMA_0(x) ((ROTR((x), 7)) ^ (ROTR((x), 18)) ^ (SHR((x),3)))
#define SIGMA_1(x) ((ROTR((x), 17)) ^ (ROTR((x), 19)) ^ (SHR((x),10)))

#define NTH_BYTE(x, n) ((x)>>(8*(n)))&0xff

/* For SHA-1, SHA-224 and SHA-256, each message block has 512 bits, which are 
represented as a sequence of sixteen 32-bit words. */

typedef struct {
    uint32_t block[16];
} msg_block_t;

typedef struct {
    uint32_t word[64];
} message_schedule_t;


/* Constants
   These words represent the first thirty-two bits of the 
   fractional parts ofthe cube roots of the 
   first sixty-four prime numbers */

uint32_t sha256_constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* Initial values of the hash 
   These words were obtained by taking the first thirty-two bits of the fractional parts
   of the square roots of the firs eight prime numbers. */

const sha256hash_t initial_value = {
    {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
};

/* Parses the message and returns a 512 bit padded message */

unsigned char* sha256padding(unsigned char* message, uint64_t* num_bytes){

    uint64_t num_bytes_message = strlen((char*) message);
    uint64_t len = 8*num_bytes_message;

    int mod_lhs = ((len+1)%512);
    uint16_t k = (448 - mod_lhs >= 0)?(448-mod_lhs):(448-mod_lhs)+512;

    uint64_t padded_length = (len + 1 + k + 64)/8;
    unsigned char* padded_message = malloc(sizeof(unsigned char)*padded_length);

    int64_t i;
    for(i=0; i<num_bytes_message; i++) {
        padded_message[i] = message[i];
    }

    /* First byte after message */
    unsigned char first_byte = 128;
    padded_message[i] = first_byte;
    i++;

    uint16_t bytes_left = (k-7)/8;
    while(bytes_left--){
        padded_message[i] = 0;
        i++;
    }

    for(int byte_num = 7; byte_num >= 0; byte_num--) {
        padded_message[i] = NTH_BYTE(len, byte_num);
        i++;
    }

    *num_bytes = padded_length;

    return padded_message;
}

msg_block_t* create_message_block(unsigned char* padded_message, uint64_t len){
    /* Allocate space for the message block.
	   Should be exactly the number of bytes
	   of a message block times
	   the number of 512 bit blocks in the message */
    
    uint64_t number_of_512bit_blocks = (len*8)/512;
    msg_block_t* message_block = malloc(sizeof(msg_block_t)*number_of_512bit_blocks);

    for (uint64_t block = 0; block < number_of_512bit_blocks; block++) {
        for (int i=0; i < 16; i++){
            /*
			In this inner loop, we map the padded_message
			to the message_block.
			message_block[0] takes bytes 0-63,
			message_block[1] takes bytes 64-127, and so on
			The first block of message_block[0] takes
			bits 0-31, which corresponds to the first 4 bytes.
			The second block of message_block[0] block corresponds
			to to bits 32-63, or bytes 4-7, etc.. */

            message_block[block].block[i] = 0;
            message_block[block].block[i] |= SHL(padded_message[64*block + 4*i + 0], (8*3));
			message_block[block].block[i] |= SHL(padded_message[64*block + 4*i + 1], (8*2));
			message_block[block].block[i] |= SHL(padded_message[64*block + 4*i + 2], (8*1));
			message_block[block].block[i] |= SHL(padded_message[64*block + 4*i + 3], (8*0));
        }
    }

    free(padded_message);
    return message_block;
}

sha256hash_t sha256sum(unsigned char* message){
    static sha256hash_t result;

    /* Variables used in the iterations 
	   for each 512-bit block */

    message_schedule_t schedule;
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    uint64_t n;

    /* Preprocessing */
    unsigned char* padded_message = sha256padding(message, &n);
    sha256hash_t H = initial_value;

    msg_block_t* message_block = create_message_block(padded_message, n);

    n = (n*8)/512;

    for(uint64_t i = 0; i < n; i++){

        for (int t = 0; t < 16; t++){
            schedule.word[t] = message_block[i].block[t];
        }

        for(int t = 16; t < 64; t++) {
            schedule.word[t] = SIGMA_1(schedule.word[t-2]) + schedule.word[t-7] + SIGMA_0(schedule.word[t-15]) + schedule.word[t-16];
        }

        a = H.word[0];
		b = H.word[1];
		c = H.word[2];
		d = H.word[3];
		e = H.word[4];
		f = H.word[5];
		g = H.word[6];
		h = H.word[7];

        for(int t=0; t <64; t++){
            t1 = h + (B_SIGMA_1(e)) + (CH(e,f,g)) + sha256_constants[t] + schedule.word[t];
			t2 = (B_SIGMA_0(a)) + (MAJ(a,b,c));

			h = g;
			g = f;
			f = e;
			e = d + t1;
			d = c;
			c = b;
			b = a;
			a = t1 + t2;
        }

        H.word[0] = a + H.word[0];
		H.word[1] = b + H.word[1];
		H.word[2] = c + H.word[2];
		H.word[3] = d + H.word[3];
		H.word[4] = e + H.word[4];
		H.word[5] = f + H.word[5];
		H.word[6] = g + H.word[6];
		H.word[7] = h + H.word[7];		

    }

    free(message_block);
	memcpy(result.word, H.word, 8*sizeof(uint32_t));
	return result;

}

unsigned char* sha256_to_string(sha256hash_t hash){
	
	static unsigned char result[64 + 1];
	result[32] = '\0';
	for(int i = 0; i < 8; i++){
    	sprintf((char*)&result[8*i + 0], "%02x", (char)NTH_BYTE(hash.word[i], 3));
    	sprintf((char*)&result[8*i + 2], "%02x", (char)NTH_BYTE(hash.word[i], 2));
    	sprintf((char*)&result[8*i + 4], "%02x", (char)NTH_BYTE(hash.word[i], 1));
    	sprintf((char*)&result[8*i + 6], "%02x", (char)NTH_BYTE(hash.word[i], 0));
	}

	return result;
}