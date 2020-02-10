// -*- coding: utf-8 -*-

#include <stdio.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include <string.h>

int md5(char* buffer);

int main(int argc, char *argv[])
{
  md5(argv[1]);
}

int md5(char *buffer )
{
  MD5_CTX contexte;
  MD5_Init (&contexte);
  int size =strlen(buffer);
  printf("%d \n",size);
  MD5_Update (&contexte, buffer, size);// Digestion du morceau
  unsigned char resume_md5[MD5_DIGEST_LENGTH];
  MD5_Final (resume_md5, &contexte);
  printf("Le résumé MD5 du mdp vaut:");
  for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", resume_md5[i]);
  printf("\n");
  exit(EXIT_SUCCESS);
}
