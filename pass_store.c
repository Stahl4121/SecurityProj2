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
  int ret = -1;
  int idx = 0;
  char *lineBuf = NULL;
  size_t len = 0;
  size_t num_pass = 0;
  user_pass_t *retPasswords = (*passwords_out);

  FILE *pass_file = fopen(PASS_FILE_PATH, "r");
  if(!pass_file) goto cleanup;

  //Count number of passwords for purposes of mem allocation
  while(getline(&lineBuf, &len, pass_file) != -1) {
    num_pass = num_pass + 1;
  }
  fseek(pass_file, 0, SEEK_SET);

  fprintf(stderr, "%zu", num_pass);

  retPasswords = malloc(sizeof(user_pass_t) * num_pass);
  if(!retPasswords) goto cleanup;

  while(getline(&lineBuf, &len, pass_file) != -1) {
    /////////////////////////////////////////////////////////
    //Is this doubly allocating?????
    /////////////////////////////////////////////////////////

    user_pass_t *user = malloc(sizeof(user_pass_t));
    char *strPtr;
    char *line = lineBuf;

    strPtr = strsep(&line, ":");                                         //Load Username
    size_t bytes = ( ( ((char*)line) - ((char*)strPtr) ) * sizeof(char));  //Get length of username
    memcpy((*user).username, strPtr, bytes); //Copy username into struct

    strsep(&line, "$"); //Clear $ before the hashID
    strsep(&line, "$"); //Clear hashID

    strPtr = strsep(&line, "$");                                  //Load salt
    bytes = (( ((char*)line) - ((char*)strPtr) ) * sizeof(char));   //Get length of salt
    memcpy((*user).salt, strPtr, bytes);      //Copy username into struct

    strPtr = line; //Load password hash as the remainder of the string
    bytes = (( ((char*)line) - ((char*)strPtr) ) * sizeof(char));   //Get length of password hash
    memcpy((*user).pass_hash, strPtr, SHA512_DIGEST_LENGTH*sizeof(char)); //Copy pass_hash into struct

    fprintf(stderr, "%s  ||  %s  ||  %s\n", (*user).username, (*user).salt, (*user).pass_hash);

    retPasswords[idx] = *user;
    idx = idx + 1;
  }

  ret = 0;

  //Update num_pass_out
  num_pass_out = &num_pass;

  cleanup:
    fclose(pass_file);
    free(lineBuf);
  
  return ret;
}


static int __pass_store_save(user_pass_t *passwords, size_t num_pass, int append)
{
  FILE *tempFile = fopen(PASS_FILE_PATH, "w");              //Clear current file
  FILE *passFile = freopen(PASS_FILE_PATH, "a", tempFile);  //Reopen in append mode

  if(!passFile){
    fclose(passFile);
    return -1;
  }

  for(int i=0; i < num_pass; i++){
    fprintf(passFile, "%s:$6$%s$%s\n", passwords[i].username, passwords[i].salt, passwords[i].pass_hash);
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
  // int ret = 0;
  // user_pass_t *passwords = NULL;
  // size_t num_pass_out = 0;
  // pass_store_load(&passwords, &num_pass_out);
  // ///////////////////////////////////////
  // //// GENERATE THE SALT FROM RAND //////
  // ///////////////////////////////////////
  // fprintf(stderr, "in pass_store_add_user \n");
  // // create password's salt
  // unsigned char salt[SALT_LEN];
  // fprintf(stderr, "after salt = null \n");
  // if(!RAND_bytes(salt, SALT_LEN)) ret = -1; 
  // fprintf(stderr, "the salt is: %s", salt);

  // //////////////////////////////
  // /// BASE64 ENCODE THE SALT ///
  // //////////////////////////////
  
  // // Base64 filter
  // BIO *b64_salt_bio = BIO_new(BIO_f_base64());
  // // Memory buffer sink
  // BIO *enc_salt_bio = BIO_new(BIO_s_mem());
  // // chain the Base64 filter to the memory buffer sink
  // BIO_push(b64_salt_bio, enc_salt_bio);
  // // // Base64 encoding by default contains new lines.
  // // // Do not output new lines.
  // // BIO_set_flags(b64_salt_bio, BIO_FLAGS_BASE64_NO_NL);
  // // // Input salt into the Base64 filter and flush the filter.
  // BIO_write(b64_salt_bio, salt, SALT_LEN);
  // BIO_flush(b64_salt_bio);

  // // Get pointer and length of data in the memory buffer sink
  // char *b64_salt[SALT_LEN_BASE64];
  // if(SALT_LEN_BASE64 != BIO_get_mem_data(enc_salt_bio, &b64_salt)) ret = -1;
  // fprintf(stderr, "base64 salt: %s", b64_salt);
  
  // ///////////////////////////////////////////
  // // CONCATENATE PASSWORD AND BASE64 SALT ///
  // ///////////////////////////////////////////
  // int pass_len = strlen(password);
  // int pass_and_salt_len = pass_len + SALT_LEN_BASE64 + 1;
  // char pass_and_salt[pass_and_salt_len];
  // strncat(pass_and_salt, password, pass_len);
  // strncat(pass_and_salt, b64_salt, SALT_LEN_BASE64);
  // fprintf(stderr, "concatenated password and salt: %s", pass_and_salt);
  
  // ////////////////////////////////////////
  // /// SHA 512 PASSWORD AND BASE64 SALT ///
  // ////////////////////////////////////////
  // char *sha_pass_salt[SHA512_DIGEST_LENGTH];
  // SHA512(pass_and_salt, pass_and_salt_len, sha_pass_salt);
  
  // /////////////////////////////////////////////////////////
  // /// B64 THE SHA512 USERNAME WITH SALTED PASSWORD HASH ///
  // /////////////////////////////////////////////////////////
  
  // // Base64 filter
  // BIO *b64_salt_and_pass_bio = BIO_new(BIO_f_base64());
  // // Memory buffer sink
  // BIO *enc_salt_and_pass_bio = BIO_new(BIO_s_mem());
  // // chain the Base64 filter to the memory buffer sink
  // BIO_push(b64_salt_and_pass_bio, enc_salt_and_pass_bio);
  // // Base64 encoding by default contains new lines.
  // // Do not output new lines.
  // BIO_set_flags(b64_salt_and_pass_bio, BIO_FLAGS_BASE64_NO_NL);
  // // Input data into the Base64 filter and flush the filter.
  // BIO_write(b64_salt_and_pass_bio, sha_pass_salt, SHA512_DIGEST_LENGTH);
  // BIO_flush(b64_salt_and_pass_bio);

  // // Get pointer and length of data in the memory buffer sink
  // char *b64_pass_and_salt[SHA512_DIGEST_LENGTH_BASE64];
  // BIO_get_mem_data(enc_salt_and_pass_bio, &b64_pass_and_salt);

  
  // struct user_pass_t new_pass_entry;
  // new_pass_entry.username = username;
  // new_pass_entry.pass_hash = b64_pass_and_salt;
  // new_pass_entry.salt = salt;

  // ///////////////////////////////////////////////////
  // /// NEED TO ADD new_pass_entry TO **passwords /////
  // /// AND NEED TO ADD THE STRING BELOW TO THE TXT ///
  // ///////////////////////////////////////////////////
  
  // // the string format is below, the struct is above. I don't have 
  // // it set up correctly with her helper functions
  // // Dr. Al Moakar wanted us to be using the password 
  // // struct array and writing to the txt file

  // // username:$6$[encoded password salt]$[encoded salted password hash]
  // pass_store_save(passwords, num_pass_out + 1, 1)
  
  // // Finally, free the BIO objects
  // BIO_free_all(b64_salt_bio);
  // BIO_free_all(b64_salt_and_pass_bio);

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
  // load all the users into the array of structs

  // iterate through them to find the user

  // set USERNAME to NULL in the array

  // resave the struct/password file


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
  // copy paste from the pass_store_add_user to regenerate the 
  // encoded password

  // then copy paste from pass_store_remove_user to find the user

  // instead of setting username to NULL, compare the above encoded generation
  // of the password with the username's stored password.
  
  user_pass_t *passwords = NULL;
  size_t num_pass_out = 0;
  __pass_store_load(&passwords, &num_pass_out);

  return 0;
}

