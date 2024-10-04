#ifndef CRYPTO_MONITOR_H
#define CRYPTO_MONITOR_H

#include <linux/types.h>

// Dichiarazioni delle costanti
#define SHA256_LENGTH 32
#define SALT_LENGTH 16

// Dichiarazioni delle funzioni
int hash_password(const char *plaintext, const unsigned char *salt, unsigned char *output);
int constant_time_compare(const unsigned char *a, const unsigned char *b, size_t length);
int compare_hash(const char *password, unsigned char *salt, unsigned char *hash_passwd);

#endif // CRYPTO_MONITOR_H
