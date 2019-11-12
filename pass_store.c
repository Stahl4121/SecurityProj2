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
  ///////////////////////////////////////
  //// SALT AND HASH THE PASSWORD ///////
  ///////////////////////////////////////

  // create password's salt
  unsigned char *salt = NULL;
  if(!RAND_bytes(salt, SALT_LEN)) {
    fprintf(stderr, "rand bytes didn't return properly");
    // free salt
    salt = NULL;
  }
  // Base64 filter
  BIO *b64_salt_bio = BIO_new(BIO_f_base64());
  // Memory buffer sink
  BIO *enc_salt_bio = BIO_new(BIO_s_mem());
  // chain the Base64 filter to the memory buffer sink
  BIO_push(b64_salt_bio, enc_salt_bio);
  // Base64 encoding by default contains new lines.
  // Do not output new lines.
  BIO_set_flags(b64_salt_bio, BIO_FLAGS_BASE64_NO_NL);
  // Input salt into the Base64 filter and flush the filter.
  BIO_write(b64_salt_bio, salt, SALT_LEN);
  BIO_flush(b64_salt_bio);

  // Get pointer and length of data in the memory buffer sink
  char *b64_salt = NULL;
  if(SALT_LEN_BASE64 != BIO_get_mem_data(enc_salt_bio, &b64_salt)) {
    fprintf(stderr, "salt len base 64 doesn't have correct length");
    // free salt and b64_salt
    free(salt);
    free(b64_salt);
    // free bios
    BIO_free(b64_salt_bio);
    BIO_free(enc_salt_bio);
  }
  fprintf(stderr, "base64 salt: %s", b64_salt);

  // concatenate password and base64 salt
  int pass_len = strlen(password);
  char pass_and_salt[pass_len + SALT_LEN_BASE64];
  int pass_and_salt_len = pass_len + SALT_LEN_BASE64;
  strncat(pass_and_salt, password, pass_len);
  strncat(pass_and_salt, b64_salt, SALT_LEN_BASE64);
  fprintf(stderr, "concatenated password and salt: %s", pass_and_salt);
  /*
  ///////////////////////////////////////////////
  /// B64 USERNAME WITH SALTED PASSWORD HASH ////
  ///////////////////////////////////////////////
  
  // sample buffer with data to Base64 encode
  uint8_t buf[24];

  // Base64 filter
  BIO *b64_salt_and_pass_bio = BIO_new(BIO_f_base64());

  // Memory buffer sink
  BIO *enc_salt_and_pass_bio = BIO_new(BIO_s_mem());

  // chain the Base64 filter to the memory buffer sink
  BIO_push(b64_salt_and_pass_bio, enc_salt_and_pass_bio);

  // Base64 encoding by default contains new lines.
  // Do not output new lines.
  BIO_set_flags(b64_salt_and_pass_bio, BIO_FLAGS_BASE64_NO_NL);

  // Input data into the Base64 filter and flush the filter.
  BIO_write(b64_salt_and_pass_bio, pass_and_salt, pass_and_salt_len);
  BIO_flush(b64_salt_and_pass_bio);

  // Get pointer and length of data in the memory buffer sink
  char *b64_pass_and_salt = NULL;
  long b64_pass_and_salt_len = BIO_get_mem_data(enc_salt_and_pass_bio, &b64_pass_and_salt);

  // Finally, free the BIO objects
  BIO_free_all(b64_bio);

  // username:$6$[encoded password salt]$[encoded salted password hash]

  // Finally, free the BIO objects
  BIO_free_all(b64_bio);
  */

  cleanup:
    fprintf(stderr, "IN CLEANUP");
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
  // FIND USER

  // DELETE USER NAME FROM THE PASSWORD

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
  ///////////////////////////////////////
  //// SALT AND HASH THE PASSWORD ///////
  ///////////////////////////////////////

  // sample buffer already populate with data to Base64 decode
  uint8_t buf[32];
  // output buffer
  uint8_t out_buf[24];

  /////////////////////////////////////////////
  //// FILL buf WITH THE CORRECT STUFF ////
  /////////////////////////////////////////////


  // Memory buffer source
  BIO *enc_bio = BIO_new_mem_buf(buf, 32);
  // Base64 filter
  BIO *b64_bio = BIO_new(BIO_f_base64());
  // Chain the memory buffer source to the Base64 filter
  BIO_push(b64_bio, enc_bio);
  // Base64 encoding by default contains new lines.
  // This Base64 encoded data doesn’t have new lines.
  BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
  // Extract decoded data from Base64 filter into output buffer
  int num_read = BIO_read(b64_bio, out_buf, 24);

  ///////////////////////////////////////////////
  /// compare USERNAME's PASSWORD w/ the stored one ////
  ///////////////////////////////////////////////

  // username:$6$[encoded password salt]$[encoded salted password hash]

  // Finally, free the BIO objects
  BIO_free_all(b64_bio);

  return 0;
}

