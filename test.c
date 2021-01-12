#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sha256.h"

int main(){

	char* input  = "hello";
	char* output = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

	sha256hash_t result = sha256sum((unsigned char*)input);
	unsigned char* result_str = sha256_to_string(result);
	printf("Result: %s\n", !strcmp(output, (char*)result_str) ? "SUCCESS":"FAILURE");

	return 0;
}