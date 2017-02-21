#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/pem.h>

// I'm not using BIO for base64 encoding/decoding.  It is difficult to use.
// Using superwills' Nibble And A Half instead 
// https://github.com/superwills/NibbleAndAHalf/blob/master/NibbleAndAHalf/base64.h
#include "base64.h"

// The PADDING parameter means RSA will pad your data for you
// if it is not exactly the right size
//#define PADDING RSA_PKCS1_OAEP_PADDING
#define PADDING RSA_PKCS1_PADDING
//#define PADDING RSA_NO_PADDING

RSA* loadPUBLICKeyFromString( const char* publicKeyStr )
{
  // A BIO is an I/O abstraction (Byte I/O?)
  
  // BIO_new_mem_buf: Create a read-only bio buf with data
  // in string passed. -1 means string is null terminated,
  // so BIO_new_mem_buf can find the dataLen itself.
  // Since BIO_new_mem_buf will be READ ONLY, it's fine that publicKeyStr is const.
  BIO* bio = BIO_new_mem_buf( (void*)publicKeyStr, -1 ) ; // -1: assume string is null terminated
  
  BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL
  
  // Load the RSA key from the BIO
  RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY( bio, NULL, NULL, NULL ) ;
  if( !rsaPubKey )
    printf( "ERROR: Could not load PUBLIC KEY!  PEM_read_bio_RSA_PUBKEY FAILED: %s\n", ERR_error_string( ERR_get_error(), NULL ) ) ;
  
  BIO_free( bio ) ;
  return rsaPubKey ;
}

RSA* loadPRIVATEKeyFromString( const char* privateKeyStr )
{
  BIO *bio = BIO_new_mem_buf( (void*)privateKeyStr, -1 );
  //BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL
  RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey( bio, NULL, NULL, NULL ) ;
  
  if ( !rsaPrivKey )
    printf("ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));
  
  BIO_free( bio ) ;
  return rsaPrivKey ;
}

unsigned char* rsaEncrypt( RSA *pubKey, const unsigned char* str, int dataSize, int *resultLen )
{
  int rsaLen = RSA_size( pubKey ) ;
  unsigned char* ed = (unsigned char*)malloc( rsaLen ) ;
  
  // RSA_public_encrypt() returns the size of the encrypted data
  // (i.e., RSA_size(rsa)). RSA_private_decrypt() 
  // returns the size of the recovered plaintext.
  *resultLen = RSA_public_encrypt( dataSize, (const unsigned char*)str, ed, pubKey, PADDING ) ; 
  if( *resultLen == -1 )
    printf("ERROR: RSA_public_encrypt: %s\n", ERR_error_string(ERR_get_error(), NULL));

  return ed ;
}

unsigned char* rsaDecrypt( RSA *privKey, const unsigned char* encryptedData, int *resultLen )
{
  int rsaLen = RSA_size( privKey ) ; // That's how many bytes the decrypted data would be
  
  unsigned char *decryptedBin = (unsigned char*)malloc( rsaLen ) ;
  *resultLen = RSA_private_decrypt( RSA_size(privKey), encryptedData, decryptedBin, privKey, PADDING ) ;
  if( *resultLen == -1 )
    printf( "ERROR: RSA_private_decrypt: %s\n", ERR_error_string(ERR_get_error(), NULL) ) ;
    
  return decryptedBin ;
}

// You may need to encrypt several blocks of binary data (each has a maximum size
// limited by pubKey).  You shoudn't try to encrypt more than
// RSA_LEN( pubKey ) bytes into some packet.
// returns base64( rsa encrypt( <<binary data>> ) )
// base64OfRsaEncrypted()
// base64StringOfRSAEncrypted
// rsaEncryptThenBase64
char* rsaEncryptThenBase64( RSA *pubKey, unsigned char* binaryData, int binaryDataLen, int *outLen )
{
  int encryptedDataLen ;
  
  // RSA encryption with public key
  unsigned char* encrypted = rsaEncrypt( pubKey, binaryData, binaryDataLen, &encryptedDataLen ) ;
  
  // To base 64
  int asciiBase64EncLen ;
  char* asciiBase64Enc = base64( encrypted, encryptedDataLen, &asciiBase64EncLen ) ;
  
  // Destroy the encrypted data (we are using the base64 version of it)
  free( encrypted ) ;
  
  // Return the base64 version of the encrypted data
  return asciiBase64Enc ;
}

// rsaDecryptOfUnbase64()
// rsaDecryptBase64String()
// unbase64ThenRSADecrypt()
// rsaDecryptThisBase64()
unsigned char* rsaDecryptThisBase64( RSA *privKey, char* base64String, int *outLen )
{
  int encBinLen ;
  unsigned char* encBin = unbase64( base64String, (int)strlen( base64String ), &encBinLen ) ;
  
  // rsaDecrypt assumes length of encBin based on privKey
  unsigned char *decryptedBin = rsaDecrypt( privKey, encBin, outLen ) ;
  free( encBin ) ;
  
  return decryptedBin ;
}
  


int main( int argc, const char* argv[] )
{
  ERR_load_crypto_strings();  
  
  // public key
  // http://srdevspot.blogspot.ca/2011/08/openssl-error0906d064pem.html
  //1. The file must contain:
  //-----BEGIN CERTIFICATE-----
  //on a separate line (i.e. it must be terminated with a newline).
  //2. Each line of "gibberish" must be 64 characters wide.
  //3. The file must end with:
  //-----END CERTIFICATE-----
  // YOUR PUBLIC KEY MUST CONTAIN NEWLINES.  If it doesn't (ie if you generated it with
  // something like
  // ssh-keygen -t rsa -C "you@example.com"
  // ) THEN YOU MUST INSERT NEWLINES EVERY 64 CHRS (just line it up with how I have it here
  // or with how the ssh-keygen private key is formatted by default)
  const char *b64_pKey = "-----BEGIN PUBLIC KEY-----\n"
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDP2SYzFccMwZxC05Uxwei6ijFc\n"
  "OoJOHPHBK2oRX6ZVDSZMxb7ghH1HU63abxzcW/+OC845OlxC5XZA9AZtfgEHdYNp\n"
  "EGyaCHE1zu4LsWiovTLpYhV1Ya9Ks/6ynUecn1P8D3OAKaCuD3DLlawLCRmWlc2E\n"
  "pnwYuJIrEf/OnB7A2QIDAQAB\n"
  "-----END PUBLIC KEY-----\n";
  
  // private key
  const char *b64priv_key = "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIICXAIBAAKBgQDP2SYzFccMwZxC05Uxwei6ijFcOoJOHPHBK2oRX6ZVDSZMxb7g\n"
  "hH1HU63abxzcW/+OC845OlxC5XZA9AZtfgEHdYNpEGyaCHE1zu4LsWiovTLpYhV1\n"
  "Ya9Ks/6ynUecn1P8D3OAKaCuD3DLlawLCRmWlc2EpnwYuJIrEf/OnB7A2QIDAQAB\n"
  "AoGAEsWa9Jwv6RAHa+WuINtRiJ94i8rg/+sPTpH8N2t7G01fuylU7vQoWGvPVN4a\n"
  "LjDE6PBaBMMnmAcfYghoGDV8JCWlgxza69JLG6BC/ug4AxKbPVN20okQSkXIRzKQ\n"
  "2y+nyLk/ud2UJ5revYKv9Off/Byh6cFQJJMXTMB/SQNzJ4ECQQDqwP9T1i2EVMxo\n"
  "GkYJWyYeKFcUFoHyjH+7cNitlMgd4f4+t7CpkiaXDNRu9nYuUC+T3KNJb/r1kuiQ\n"
  "HUcZNVeRAkEA4qjGn3p/fmer0YruTX1X8xBIk0bgaKfnTAD8Mo/DvtzCu9L85m4P\n"
  "y4DMDh9u40/TXeP5kvEh/XovRQedwO0AyQJBAL5WR28hO/yMiMNrchfJ6KkRCjGG\n"
  "YkxXsIU45OYwuOTJxMvzQfDrSBC23VMuz/mTGFBp15cGjVMpjxiyNGBzCJECQBgA\n"
  "f2gL9MxR9iPubmXOTC31H3pZGxJ6FUg7InnIN5ZSklyJbzaHmSyXqwQj1/5CScO7\n"
  "jIY++rZ45eCNeesgLeECQFyzTM+ZcpJmD0gHrR9HOZVRGxuY4VEnlmXskmDofozU\n"
  "62iHAnRxrSv8I1Fiafok33wS7QkLu3Zq4WqifNsmRwQ=\n"
  "-----END RSA PRIVATE KEY-----\n";

  // String to encrypt, INCLUDING NULL TERMINATOR:
  int dataSize=6;
  unsigned char str[] = "12345";
  printf( "The original data is:%s\n\n", (char*)str);
  
  // LOAD PUBLIC KEY
  RSA *pubKey = loadPUBLICKeyFromString( b64_pKey ) ;
  
  int asciiB64ELen ;
  char* asciiB64E = rsaEncryptThenBase64( pubKey, str, dataSize, &asciiB64ELen ) ;
   
  RSA_free( pubKey ) ; // free the public key when you are done all your encryption
  
  printf( "base64_encoded(rsa_encrypted()):\n%s\n\n", asciiB64E ) ;
  
  // Now decrypt this very string with the private key
  RSA *privKey = loadPRIVATEKeyFromString( b64priv_key ) ;
  
  // Now we got the data at the server.  Time to decrypt it.
  int rBinLen ;
  unsigned char* rBin = rsaDecryptThisBase64( privKey, asciiB64E, &rBinLen ) ;
  printf("Decrypted %d bytes, the recovered data is:\n%.*s\n\n", rBinLen, rBinLen, rBin ) ; // rBin is not necessarily NULL
  // terminated, so we only print rBinLen chrs
  
  RSA_free(privKey) ;
  
  free( asciiB64E ) ; // rxOverHTTP  
  free( rBin ) ;
  ERR_free_strings();
}
