#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "pass_store.h"

#define SALT_LEN 8

// Every 3 bytes of salt encoded as 4 characters + possible padding
#define SALT_LEN_BASE64 (SALT_LEN/3 + 1) * 4
#define SHA512_DIGEST_LENGTH_BASE64 (SHA512_DIGEST_LENGTH/3 + 1) * 4

#define MAX_USER_LEN 32
#define PASS_FILE_PATH "passwords"

typedef struct user_pass_s {
  // NULL-terminated username string
  // if username is empty, consider the entry removed
  char username[MAX_USER_LEN];
  // binary password hash (no encoding)
  uint8_t pass_hash[SHA512_DIGEST_LENGTH];
  // NULL-terminated Base64 encoded salt string
  char salt[SALT_LEN_BASE64+1];
} user_pass_t;


static int __pass_store_load(user_pass_t **passwords_out, size_t *num_pass_out)
{
  return 0;
}


static int __pass_store_save(user_pass_t *passwords, size_t num_pass, int append)
{
  return 0;
}


/*
 * pass_store_add_user - adds a new user to the password store
 *
 * @username: NULL-delimited username string
 * @password: NULL-delimited password string
 *
 * Returns 0 on success, -1 on failure
 */
int pass_store_add_user(const char *username, const char *password)
{
  return 0;
}


/* 
 * pass_store_remove_user - removes a user from the password store
 *
 * @username: NULL-delimited username string
 *
 * Returns 0 on success, -1 on failure
 */
int pass_store_remove_user(const char *username)
{
  return 0;
}


/*
 * pass_store_check_password - check the password of a user
 *
 * @username: NULL-delimited username string
 * @passwrod: NULL-delimited password string
 *
 * Returns 0 on success, -1 on failure
 */
int pass_store_check_password(const char *username, const char *password)
{
  return 0;
}

