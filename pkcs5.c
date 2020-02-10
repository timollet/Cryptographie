#include "pkcs5.h"

int pkcs5(char *nom_du_fichier);

void main()
{
  pkcs5("butokuden.jpg");
}

int pkcs5(char *nom_du_fichier)
{
  int size = 0;
  int i;
  int size_add = 0;
  int  nb_octets_lus;
  int nb_octets_ecrit;
  unsigned char value;
  unsigned char buffer[1024];
  // On ouvre le fichier
  FILE *fichier = fopen (nom_du_fichier, "r+");
  if (fichier == NULL)
  {
    printf ("Le fichier %s ne peut pas être ouvert.\n", nom_du_fichier);
    return 0;
  }

  while (nb_octets_lus != 0) {
   nb_octets_lus = fread (buffer, 1, sizeof(buffer), fichier); // Lecture du morceau
   size = nb_octets_lus + size;
  }
  printf("%d\n",size);
  size_add=16-size%16;
  printf("%d\n",size_add);
  value =size_add;
  for(i=0;i<size_add;i++)
  {
    nb_octets_ecrit = fwrite(&value,1,1, fichier);
  }

  size = nb_octets_ecrit + size;
  fclose (fichier);
  printf("%d\n",size);
}
