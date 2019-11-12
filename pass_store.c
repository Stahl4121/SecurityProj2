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
  int idx = 0;
  char *lineBuf = NULL;
  size_t len = 0;
  size_t num_pass = 0;

  FILE *pass_file = fopen(PASS_FILE_PATH, "r");
  if(!pass_file){
    fclose(pass_file);
    return -1;
  }

  //Count number of passwords for purposes of mem allocation
  while(getline(&lineBuf, &len, pass_file) != -1) {
    num_pass = num_pass + 1;
  }
  fseek(pass_file, 0, SEEK_SET);

  user_pass_t retPasswords[num_pass];

  while(getline(&lineBuf, &len, pass_file) != -1) {
    char *strPtr;
    char *line = lineBuf;

    strPtr = strsep(&line, ":");                                         //Load Username
    size_t bytes = ( ( ((char*)line) - ((char*)strPtr) ) * sizeof(char));  //Get length of username
    memcpy(retPasswords[idx].username, strPtr, bytes); //Copy username into struct

    strsep(&line, "$"); //Clear $ before the hashID
    strsep(&line, "$"); //Clear hashID

    strPtr = strsep(&line, "$");                                  //Load salt
    bytes = (( ((char*)line) - ((char*)strPtr) ) * sizeof(char));   //Get length of salt
    memcpy(retPasswords[idx].salt, strPtr, bytes);      //Copy username into struct

    strPtr = line; //Load password hash as the remainder of the string
    bytes = SHA512_DIGEST_LENGTH*sizeof(char);   //Get length of password hash

    /*
    *   Decode Base64 encoding from stored password hash 
    */

    // Memory buffer source
    BIO *enc_bio = BIO_new_mem_buf(strPtr, SHA512_DIGEST_LENGTH_BASE64);
    // Base64 filter
    BIO *b64_bio = BIO_new(BIO_f_base64());
    // Chain the memory buffer source to the Base64 filter
    BIO_push(b64_bio, enc_bio);
    // Base64 encoding by default contains new lines.
    // This Base64 encoded data doesn’t have new lines.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    // Extract decoded data from Base64 filter into output buffer
    int num_read = BIO_read(b64_bio, retPasswords[idx].pass_hash, bytes);
    if(num_read <= 0) {
      fclose(pass_file);
      free(lineBuf);
      BIO_free_all(b64_bio);
      return -1;
    }
    // Finally, free the BIO objects
    BIO_free_all(b64_bio);

    idx = idx + 1;
  }

  //Close file and free memory buffer
  fclose(pass_file);
  free(lineBuf);

  //Update passwords_out 
  *passwords_out = malloc(sizeof(user_pass_t)*num_pass);
  memset((*passwords_out), 0, (sizeof(user_pass_t)*num_pass));
  memcpy((*passwords_out), retPasswords, sizeof(user_pass_t)*num_pass); //Copy over struct array

  //Update num_pass_out
  *num_pass_out = num_pass;

  return 0;
}


static int __pass_store_save(user_pass_t *passwords, size_t num_pass, int append)
{
  FILE *tempFile = fopen("passwords333", "w");              //Clear current file
  FILE *passFile = freopen("passwords333", "a", tempFile);  //Reopen in append mode

  if(!passFile){
    fclose(passFile);
    return -1;
  }

  for(int i=0; i < (int) num_pass; i++){
    /*
    *   Encode Base64 encoding for storing password hash 
    */

    // Base64 filter
    BIO *b64_bio = BIO_new(BIO_f_base64());
    // Memory buffer sink
    BIO *enc_bio = BIO_new(BIO_s_mem());
    // chain the Base64 filter to the memory buffer sink
    BIO_push(b64_bio, enc_bio);
    // Base64 encoding by default contains new lines.
    // Do not output new lines.
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    // Input data into the Base64 filter and flush the filter.
    BIO_write(b64_bio, passwords[i].pass_hash, SHA512_DIGEST_LENGTH);
    BIO_flush(b64_bio);

    // Get pointer and length of data in the memory buffer sink
    char *pass_hash_ptr = NULL;
    long data_len = BIO_get_mem_data(enc_bio, &pass_hash_ptr);

    if(data_len <= 0){
      fclose(passFile);
      BIO_free_all(b64_bio);
      return -1;
    }

    //Output password struct to file
    fprintf(passFile, "%s:$6$%s$%s\n", passwords[i].username, passwords[i].salt, pass_hash_ptr);
    
    // Finally, free the BIO objects
    BIO_free_all(b64_bio);
  }
  
  fclose(passFile);

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
  int ret = 0;
  int repeat_username = 0;
  user_pass_t *passwords = NULL;
  size_t num_pass_out = 0;
  __pass_store_load(&passwords, &num_pass_out);

  /////////////////////////////////////
  /// CHECK FOR DUPLICATE USERNAMES ///
  /////////////////////////////////////
  for(int i = 0; i < num_pass_out; i++) {
    if(username == passwords[i].username) { repeat_username = 1;}
  }

  if(!repeat_username) {
    ///////////////////////////////////////
    //// GENERATE THE SALT FROM RAND //////
    ///////////////////////////////////////
    fprintf(stderr, "in pass_store_add_user \n");
    // create password's salt
    unsigned char salt[SALT_LEN];
    //fprintf(stderr, "after salt = null \n");
    if(!RAND_bytes(salt, SALT_LEN)) ret = -1; 
    //fprintf(stderr, "the salt is: %s", salt);

    //////////////////////////////
    /// BASE64 ENCODE THE SALT ///
    //////////////////////////////
    
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
    unsigned char b64_salt[SALT_LEN_BASE64];
    if(SALT_LEN_BASE64 != BIO_get_mem_data(enc_salt_bio, &b64_salt)) ret = -1;
    //fprintf(stderr, "base64 salt: %s", b64_salt);
    
    ///////////////////////////////////////////
    // CONCATENATE PASSWORD AND BASE64 SALT ///
    ///////////////////////////////////////////
    int pass_len = strlen(password);
    int pass_and_salt_len = pass_len + SALT_LEN_BASE64 + 1;
    unsigned char *pass_and_salt;
    pass_and_salt = malloc(sizeof(pass_and_salt_len));
    memcpy(pass_and_salt, password, pass_len);
    memcpy(pass_and_salt, b64_salt, SALT_LEN_BASE64);
    //fprintf(stderr, "concatenated password and salt: %s", pass_and_salt);
    
    ////////////////////////////////////////
    /// SHA 512 PASSWORD AND BASE64 SALT ///
    ////////////////////////////////////////
    uint8_t sha_pass_salt[SHA512_DIGEST_LENGTH];
    SHA512(pass_and_salt, pass_and_salt_len, (unsigned char*)sha_pass_salt);
    
    user_pass_t new_pass_entry;
    // clear out the memory of the new struct
    memset(&new_pass_entry, 0, sizeof(new_pass_entry));
    // use strncpy for username
    // use bio to copy the salt
    // use mem copy for password hash
    strncpy(new_pass_entry.username, username, strlen(username));
    memcpy(new_pass_entry.pass_hash, sha_pass_salt, SHA512_DIGEST_LENGTH);
    memcpy(new_pass_entry.salt, b64_salt, SALT_LEN_BASE64+1);
    
    ///////////////////////////////////////////////////
    /// NEED TO ADD new_pass_entry TO **passwords /////
    /// AND NEED TO ADD THE STRING BELOW TO THE TXT ///
    ///////////////////////////////////////////////////
    
    __pass_store_save(&new_pass_entry, 1, 1);
    
    // Finally, free the BIO objects
    BIO_free_all(b64_salt_bio);
  }
  
  return ret;
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
  // load all the users into the array of structs
  user_pass_t *passwords = NULL;
  size_t num_pass_out = 0;
  __pass_store_load(&passwords, &num_pass_out);

  ////////////////////////////////
  /// CHECK FOR GIVEN USERNAME ///
  ////////////////////////////////
 
  // iterate through them to find the user
  for(int i = 0; i < num_pass_out; i++) {
    // set USERNAME to NULL in the array
    if(username == passwords[i].username) {
        memset(passwords[i].username, 0, strlen(username));
      }
  }
  // resave the struct/password file
  __pass_store_save(passwords, num_pass_out, 0);
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
  int ret = 0;
  int username_exists = 0;
  user_pass_t *passwords = NULL;
  size_t num_pass_out = 0;
  __pass_store_load(&passwords, &num_pass_out);
  uint8_t correct_pass_hash[SHA512_DIGEST_LENGTH];
  ////////////////////////////////
  /// CHECK IF USERNAME EXISTS ///
  ////////////////////////////////
  for(int i = 0; i < num_pass_out; i++) {
    if(username == passwords[i].username) { 
      username_exists = 1;
      memcpy(correct_pass_hash, passwords[i].pass_hash, SHA512_DIGEST_LENGTH);
    }
  }

  ///////////////////////////
  /// ENCODE THE PASSWORD ///
  ///////////////////////////
  if(username_exists) {
    //////////////////////////////////////
    /// GENERATE THE SALT FROM RAND //////
    //////////////////////////////////////
    
    //fprintf(stderr, "in pass_store_add_user \n");
    // create password's salt
    unsigned char salt[SALT_LEN];
    //fprintf(stderr, "after salt = null \n");
    if(!RAND_bytes(salt, SALT_LEN)) ret = -1; 
    //fprintf(stderr, "the salt is: %s", salt);

    //////////////////////////////
    /// BASE64 ENCODE THE SALT ///
    //////////////////////////////
    
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
    unsigned char b64_salt[SALT_LEN_BASE64];
    if(SALT_LEN_BASE64 != BIO_get_mem_data(enc_salt_bio, &b64_salt)) ret = -1;
    //fprintf(stderr, "base64 salt: %s", b64_salt);
    
    ///////////////////////////////////////////
    // CONCATENATE PASSWORD AND BASE64 SALT ///
    ///////////////////////////////////////////
    int pass_len = strlen(password);
    int pass_and_salt_len = pass_len + SALT_LEN_BASE64 + 1;
    unsigned char *pass_and_salt;
    pass_and_salt = malloc(sizeof(pass_and_salt_len));
    memcpy(pass_and_salt, password, pass_len);
    memcpy(pass_and_salt, b64_salt, SALT_LEN_BASE64);
    //fprintf(stderr, "concatenated password and salt: %s", pass_and_salt);
    
    ////////////////////////////////////////
    /// SHA 512 PASSWORD AND BASE64 SALT ///
    ////////////////////////////////////////
    uint8_t sha_pass_salt[SHA512_DIGEST_LENGTH];
    SHA512(pass_and_salt, pass_and_salt_len, (unsigned char*)sha_pass_salt);
    
    ////////////////////////////////////////////////////////
    // COMPARE GENERATED PASS-HASH WITH CORRECT PASS-HASH //
    ////////////////////////////////////////////////////////
    if(sha_pass_salt != correct_pass_hash) {
      ret = -1;
    }

    // Finally, free the BIO objects
    BIO_free_all(b64_salt_bio);
  } else {
    ret = -1;
  }
  
  return ret;
}

