#include "aes_projet.h"

uchar Rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 } ;
// Constantes de ronde


/* La clef courte K utilisée est formée de 16 octets nuls */
int longueur_de_la_clef = 16 ;
uchar K[16];
uchar KNul[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} ;

/* Résultat du TP précédent : diversification de la clef courte K en une clef étendue W */

int Nr = 10, Nk = 4;
int longueur_de_la_clef_etendue = 176;
uchar W[176] = { 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63,
  0x9B, 0x98, 0x98, 0xC9, 0xF9, 0xFB, 0xFB, 0xAA, 0x9B, 0x98, 0x98, 0xC9, 0xF9, 0xFB, 0xFB, 0xAA,
  0x90, 0x97, 0x34, 0x50, 0x69, 0x6C, 0xCF, 0xFA, 0xF2, 0xF4, 0x57, 0x33, 0x0B, 0x0F, 0xAC, 0x99,
  0xEE, 0x06, 0xDA, 0x7B, 0x87, 0x6A, 0x15, 0x81, 0x75, 0x9E, 0x42, 0xB2, 0x7E, 0x91, 0xEE, 0x2B,
  0x7F, 0x2E, 0x2B, 0x88, 0xF8, 0x44, 0x3E, 0x09, 0x8D, 0xDA, 0x7C, 0xBB, 0xF3, 0x4B, 0x92, 0x90, 
  0xEC, 0x61, 0x4B, 0x85, 0x14, 0x25, 0x75, 0x8C, 0x99, 0xFF, 0x09, 0x37, 0x6A, 0xB4, 0x9B, 0xA7, 
  0x21, 0x75, 0x17, 0x87, 0x35, 0x50, 0x62, 0x0B, 0xAC, 0xAF, 0x6B, 0x3C, 0xC6, 0x1B, 0xF0, 0x9B, 
  0x0E, 0xF9, 0x03, 0x33, 0x3B, 0xA9, 0x61, 0x38, 0x97, 0x06, 0x0A, 0x04, 0x51, 0x1D, 0xFA, 0x9F, 
  0xB1, 0xD4, 0xD8, 0xE2, 0x8A, 0x7D, 0xB9, 0xDA, 0x1D, 0x7B, 0xB3, 0xDE, 0x4C, 0x66, 0x49, 0x41, 
  0xB4, 0xEF, 0x5B, 0xCB, 0x3E, 0x92, 0xE2, 0x11, 0x23, 0xE9, 0x51, 0xCF, 0x6F, 0x8F, 0x18, 0x8E
};

/* Le bloc à chiffrer*/
uchar State[16]; 
uchar StateNul[16]= {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} ;

/* Le vecteur d'initialisation*/
uchar Init_Vector[16];

/* Resume du md5 fait avec la fonction md5 */
uchar resume_md5[MD5_DIGEST_LENGTH];


/* Programme principal */

int main(int argc, char *argv[]) 
{
    /*Si pas d'argument passé
    On chiffre le bloc nul avec la cle nulle*/
    char *fileName = NULL;
    FILE * file = NULL;    
    char *fileNameC = NULL;
    FILE * fileC = NULL;
    int i,sizeOfFile;
    int  nb_octets_lus = -1;
    int  nb_octets_lus_tot = -1;
    int nb_octets_ecrit;
    int nb_octets_ecrit_tot;
    uchar buffer[16];
    uchar temp[16];
    struct stat sb;
    srand(time(NULL)); // initialisation de rand
    if(argc>4)
    {
        printf("Trop d'arguments \nSoit 0 argument (chiffer bloc nul avec clé nulle)\nSoit 1 argument -e (chiffer bloc nul avec clé nulle) ou -d (dechiffer bloc nul avec clé nulle)\n");
        return EXIT_FAILURE;
    }
    else if(argc == 1)
    {
        chiffrer_bloc_nul();
    }
    else if (argc == 2)
    {
        if( strcmp(argv[1], "-e") == 0)
        {
            chiffrer_bloc_nul();
        }
        else if( strcmp(argv[1], "-d") == 0)
        {
          dechiffrer_bloc_nul();
        }
        else
        {
            printf("Mauvais argument veuillez rentrer -e ou -d si vous m'étais qu'un argument \n" );
            return EXIT_FAILURE;
        }
    }
    else if(argc == 3)
    {
       if( strcmp(argv[1], "-e") == 0)
        {
            /*Recuperation du nom du fichier est ouverture de ce dernier en lecture*/
            fileName = argv[2];
            //Bourrage du fichier
            pkcs5(fileName);
            file = fopen (fileName, "r+");
            if (file == NULL)
            {
                printf ("Le fichier %s ne peut pas être ouvert.\n", fileName);
                return 0;
            }
            /*Creation du nom du fichier chiffrer et ouverture de ce dernier en ecriture*/
            
            char prefix[100]="aes-";
            fileNameC=strcat(prefix, fileName);
            fileC = fopen (fileNameC, "w+");
            if (fileC == NULL)
            {
                printf ("Le fichier %s ne peut pas être ouvert.\n", fileNameC);
                return 0;
            }
            //initialisation du vecteur d'initialisation de manière randomn
            for(i = 0 ; i<16;i++)
            {
                Init_Vector[i]=rand()%(255);
                printf("%d ",Init_Vector[i]);
            }
            //ecriture de init_vector dans le fileC
            nb_octets_ecrit = fwrite(Init_Vector,1, 16, fileC);

            while (nb_octets_lus != 0) {
                nb_octets_lus = fread (buffer, 1,16, file); // Lecture du morceau
                //OU exclusif entre init vector et buffer pour initialiser State
                if (nb_octets_lus !=0)
                {
                    for(i = 0 ; i<16;i++)
                    {
                        State[i]=buffer[i] ^ Init_Vector[i];
                    }
                    //chiffrement de state
                    chiffrer();
                    //ecriture de state dans le fileC
                    nb_octets_ecrit = fwrite(State,1, 16, fileC);
                    //On remplace le init vector par le state
                    for(i = 0 ; i<16;i++)
                    {
                        Init_Vector[i]=State[i];
                    }
                }
            }
            fclose(file);
            fclose(fileC);
         }
        else if( strcmp(argv[1], "-d") == 0)
        {
             /*Recuperation du nom du fichier est ouverture de ce dernier en lecture*/
            fileName = argv[2];
            
            if (stat(fileName, &sb) == -1) {
              perror("stat");
              exit(EXIT_SUCCESS);
            }
            sizeOfFile=(int)sb.st_size;
            
            file = fopen (fileName, "r+");
            if (file == NULL)
            {
                printf ("Le fichier %s ne peut pas être ouvert.\n", fileName);
                return 0;
            }
            /*Creation du nom du fichier chiffrer et ouverture de ce dernier en ecriture*/
            char prefix[100]="aes-";
            fileNameC=strcat(prefix, fileName);
            fileC = fopen (fileNameC, "w+");
            if (fileC == NULL)
            {
                printf ("Le fichier %s ne peut pas être ouvert.\n", fileNameC);
                return 0;
            }
            nb_octets_lus = fread (buffer, 1,16, file); // Lecture du morceau
            nb_octets_lus_tot=nb_octets_lus_tot+nb_octets_lus;
            //initialisation du vecteur d'initialisation de manière randomn
            for(i = 0 ; i<16;i++)
            {
                Init_Vector[i]=buffer[i];
            }
            while (nb_octets_lus != 0) {
                nb_octets_lus = fread (buffer, 1,16, file); // Lecture du morceau
                nb_octets_lus_tot=nb_octets_lus_tot+nb_octets_lus;
                //OU exclusif entre init vector et buffer pour initialiser State
                if (nb_octets_lus !=0)
                {
                  
                  for(i = 0 ; i<16;i++)
                  {
                    temp[i]=buffer[i];
                    State[i]=buffer[i];
                  }
                  //dechiffrement de state
                  dechiffrer();
                  for(i = 0 ; i<16;i++)
                  {
                    State[i]=State[i] ^ Init_Vector[i];
                    Init_Vector[i]=temp[i];
                  }
                  if(nb_octets_lus_tot!=sizeOfFile)
                  {
                    //ecriture de state dans le fileC
                    nb_octets_ecrit = fwrite(State,1, 16, fileC);
                    nb_octets_ecrit_tot = nb_octets_ecrit_tot+nb_octets_ecrit;
                  }
                  else
                  {
                    for(i = 0 ; i<16;i++)
                    {
                      printf("%d",buffer[i]);
                    }
                    //ecriture de state dans le fileC
                    nb_octets_ecrit = fwrite(State,1, 16, fileC);
                    nb_octets_ecrit_tot = nb_octets_ecrit_tot+nb_octets_ecrit;
                  }
                }
            }
        }
    }
    else if(argc == 4)
    {

      md5(argv[3]);
      calcule_la_clef_etendue(resume_md5, 16 , W, 176, Nr, Nk);
      if( strcmp(argv[1], "-e") == 0)
      {
            /*Recuperation du nom du fichier est ouverture de ce dernier en lecture*/
            fileName = argv[2];
            //Bourrage du fichier
            pkcs5(fileName);
            file = fopen (fileName, "r+");
            if (file == NULL)
            {
                printf ("Le fichier %s ne peut pas être ouvert.\n", fileName);
                return 0;
            }
            /*Creation du nom du fichier chiffrer et ouverture de ce dernier en ecriture*/
            
            char prefix[100]="aes-";
            fileNameC=strcat(prefix, fileName);
            fileC = fopen (fileNameC, "w+");
            if (fileC == NULL)
            {
                printf ("Le fichier %s ne peut pas être ouvert.\n", fileNameC);
                return 0;
            }
            //initialisation du vecteur d'initialisation de manière randomn
            for(i = 0 ; i<16;i++)
            {
                Init_Vector[i]=rand()%(255);
                printf("%d ",Init_Vector[i]);
            }
            //ecriture de init_vector dans le fileC
            nb_octets_ecrit = fwrite(Init_Vector,1, 16, fileC);

            while (nb_octets_lus != 0) 
            {
                nb_octets_lus = fread (buffer, 1,16, file); // Lecture du morceau
                //OU exclusif entre init vector et buffer pour initialiser State
                if (nb_octets_lus !=0)
                {
                    for(i = 0 ; i<16;i++)
                    {
                        State[i]=buffer[i] ^ Init_Vector[i];
                    }
                    //chiffrement de state
                    chiffrer();
                    //ecriture de state dans le fileC
                    nb_octets_ecrit = fwrite(State,1, 16, fileC);
                    //On remplace le init vector par le state
                    for(i = 0 ; i<16;i++)
                    {
                        Init_Vector[i]=State[i];
                    }
                }
            }
            fclose(file);
            fclose(fileC);
      }
      else if( strcmp(argv[1], "-d") == 0)
          {
             /*Recuperation du nom du fichier est ouverture de ce dernier en lecture*/
            fileName = argv[2];
            if (stat(fileName, &sb) == -1) 
            {
              perror("stat");
              exit(EXIT_SUCCESS);
            }
            sizeOfFile=(int)sb.st_size;
            
            file = fopen (fileName, "r+");
            if (file == NULL)
            {
                printf ("Le fichier %s ne peut pas être ouvert.\n", fileName);
                return 0;
            }
            /*Creation du nom du fichier chiffrer et ouverture de ce dernier en ecriture*/
            char prefix[100]="aes-";
            fileNameC=strcat(prefix, fileName);
            fileC = fopen (fileNameC, "w+");
            if (fileC == NULL)
            {
                printf ("Le fichier %s ne peut pas être ouvert.\n", fileNameC);
                return 0;
            }
            nb_octets_lus = fread (buffer, 1,16, file); // Lecture du morceau
            nb_octets_lus_tot=nb_octets_lus_tot+nb_octets_lus;
            //initialisation du vecteur d'initialisation de manière randomn
            for(i = 0 ; i<16;i++)
            {
                Init_Vector[i]=buffer[i];
            }
            while (nb_octets_lus != 0) 
            {
                nb_octets_lus = fread (buffer, 1,16, file); // Lecture du morceau
                nb_octets_lus_tot=nb_octets_lus_tot+nb_octets_lus;
                //OU exclusif entre init vector et buffer pour initialiser State
                if (nb_octets_lus !=0)
                {
                  
                  for(i = 0 ; i<16;i++)
                  {
                    temp[i]=buffer[i];
                    State[i]=buffer[i];
                  }
                  //dechiffrement de state
                  dechiffrer();
                  for(i = 0 ; i<16;i++)
                  {
                    State[i]=State[i] ^ Init_Vector[i];
                    Init_Vector[i]=temp[i];
                  }
                  if(nb_octets_lus_tot!=sizeOfFile)
                  {
                    //ecriture de state dans le fileC
                    nb_octets_ecrit = fwrite(State,1, 16, fileC);
                    nb_octets_ecrit_tot = nb_octets_ecrit_tot+nb_octets_ecrit;
                  }
                  else
                  {
                    for(i = 0 ; i<16;i++)
                    {
                      printf("%d",buffer[i]);
                    }
                    //ecriture de state dans le fileC
                    nb_octets_ecrit = fwrite(State,1, 16, fileC);
                    nb_octets_ecrit_tot = nb_octets_ecrit_tot+nb_octets_ecrit;
                  }
                }
            }
          }
      }
      else
      {
            printf("Mauvais argument veuillez rentrer en premier -e ou -d et en 2eme argument le nom du fichier \n" );
            return EXIT_FAILURE;
      }
 return 1;
}

/* Fonction pour afficher un bloc */
void afficher_le_bloc(uchar *M) {
  for (int i=0; i<4; i++) { // Lignes 0 à 3
    printf("          ");
    for (int j=0; j<4; j++) { // Colonnes 0 à 3
      printf ("%02X ", M[4*j+i]); }
    printf("\n");
  }
}

/*Chiffrement bloc nul*/
void chiffrer_bloc_nul()
{
    for(int i=0; i<16;i ++)
    {
        State[i]=StateNul[i];
        K[i]=KNul[i];
    }
    printf("Le bloc a chiffrer vaut : \n");
    afficher_le_bloc(State);
    chiffrer();
    printf("Le bloc chiffré vaut : \n");
    afficher_le_bloc(State);
}
/*Dechiffrement bloc nul*/
void dechiffrer_bloc_nul()
{
        for(int i=0; i<16;i ++)
    {
        State[i]=StateNul[i];
        K[i]=KNul[i];
    }
    printf("Le bloc a chiffrer vaut : \n");
    afficher_le_bloc(State);
    dechiffrer();
    printf("Le bloc chiffré vaut : \n");
    afficher_le_bloc(State);
}





/* Fonction qui chiffre un Bloc State avec la cle K etendu en cle W */
void chiffrer(void){
  int i;
  AddRoundKey(0);
  for (i = 1; i < Nr; i++) {
    SubBytes();
    ShiftRows();
    MixColumns();
    AddRoundKey(i);
  }
  SubBytes();
  ShiftRows();
  AddRoundKey(Nr);
}
/* Fonction qui dechiffre un Bloc State avec la cle K etendu en cle W */
void dechiffrer(void){
  int i;

    AddRoundKey(Nr);
  Inv_ShiftRows();
  Inv_SubBytes();
  for (i = Nr-1; i >=1; i--) {
    AddRoundKey(i);
    Inv_MixColumns();
    Inv_ShiftRows();
    Inv_SubBytes();
  }
AddRoundKey(0);
}

/* Table de substitution déjà utilisée lors du TP précédent */

uchar SBox[256] = {
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

uchar inv_SBox[256] ;

/* Fonction mystérieuse qui calcule le produit de deux octets */

uchar gmul(uchar a, uchar b) {
  uchar p = 0;
  uchar hi_bit_set;
  int i;
  for(i = 0; i < 8; i++) {
    if((b & 1) == 1) 
      p ^= a;
    hi_bit_set = (a & 0x80);
    a <<= 1;
    if(hi_bit_set == 0x80) 
      a ^= 0x1b;		
    b >>= 1;
  }
  return p & 0xFF;
}

/* Partie à compléter pour ce TP */

void SubBytes(void){
    int i ;

  for(i=0;i<sizeof(State);i++)
  {
    State[i]=SBox[State[i]];
  }
};

void Inv_SubBytes(void)
{
  int i ;
	inverse_tab();
  for(i=0;i<sizeof(State);i++)
  {
    State[i]=inv_SBox[State[i]];
  }
};

void ShiftRows(void){
  int i;
  int temp;
  for(i=0;i<4;i++)
  {
    //si on est sur la deuxième ligne
    if(i==1)
    {
      temp = State[1];
      State[1]=State[5];
      State[5]=State[9];
      State[9]=State[13];
      State[13]=temp;
    }
    else if(i==2)
    {
      temp = State[2];
      State[2]=State[10];
      State[10]=temp;
      temp = State[6];
      State[6]=State[14];
      State[14]=temp;
    }
    else if(i==3)
    {
      temp=State[7];
      State[7]=State[3];
      State[3]=State[15];
      State[15]=State[11];
      State[11]=temp;
    }
  }
};

void Inv_ShiftRows(void){
  int i;
  int temp;
  for(i=0;i<4;i++)
  {
    //si on est sur la deuxième ligne
    if(i==1)
    {
      temp = State[5];
      State[5]=State[1];
      State[1]=State[13];
      State[13]=State[9];
      State[9]=temp;
    }
    else if(i==2)
    {
      temp = State[10];
      State[10]=State[2];
      State[2]=temp;
      temp = State[14];
      State[14]=State[6];
      State[6]=temp;
    }
    else if(i==3)
    {
      temp=State[15];
      State[15]=State[3];
      State[3]=State[7];
      State[7]=State[11];
      State[11]=temp;
    }
    else
    {
    }
  }
};

void MixColumns(void)
{
  int T[4];
  int i;
  for(i=0;i<16;i=i+4)
  {
        T[0]=gmul(0x02,State[i]) ^ gmul(0x03,State[i+1]) ^ gmul(0x01,State[i+2]) ^ gmul(0x01,State[i+3]);
        T[1]=gmul(0x01,State[i]) ^ gmul(0x02,State[i+1]) ^ gmul(0x03,State[i+2]) ^ gmul(0x01,State[i+3]);
        T[2]=gmul(0x01,State[i]) ^ gmul(0x01,State[i+1]) ^ gmul(0x02,State[i+2]) ^ gmul(0x03,State[i+3]);
        T[3]=gmul(0x03,State[i]) ^ gmul(0x01,State[i+1]) ^ gmul(0x01,State[i+2]) ^ gmul(0x02,State[i+3]);
        State[i]=T[0];
        State[i+1]=T[1];
        State[i+2]=T[2];
        State[i+3]=T[3];
  }
};

void Inv_MixColumns(void)
{
  int T[4];
  int i;
  for(i=0;i<16;i=i+4)
  {
        T[0]=gmul(0x0E,State[i]) ^ gmul(0x0B,State[i+1]) ^ gmul(0x0D,State[i+2]) ^ gmul(0x09,State[i+3]);
        T[1]=gmul(0x09,State[i]) ^ gmul(0x0E,State[i+1]) ^ gmul(0x0B,State[i+2]) ^ gmul(0x0D,State[i+3]);
        T[2]=gmul(0x0D,State[i]) ^ gmul(0x09,State[i+1]) ^ gmul(0x0E,State[i+2]) ^ gmul(0x0B,State[i+3]);
        T[3]=gmul(0x0B,State[i]) ^ gmul(0x0D,State[i+1]) ^ gmul(0x09,State[i+2]) ^ gmul(0x0E,State[i+3]);
        State[i]=T[0];
        State[i+1]=T[1];
        State[i+2]=T[2];
        State[i+3]=T[3];
  }
};

void AddRoundKey(int r){
  	int i;
	for (i=0 ; i<sizeof(State);i++)
	{
		State[i]=State[i] ^ W[r*16+i];
	}

};

void  inverse_tab()
{

	int i;
	for(i=0;i<256;i++)
	{
		inv_SBox[SBox[i]]=i;
	}

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
  //printf("%d\n",size);
  size_add=16-size%16;
  //printf("%d\n",size_add);
  value =size_add;
  for(i=0;i<size_add;i++)
  {
    nb_octets_ecrit = fwrite(&value,1,1, fichier);
  }

  size = nb_octets_ecrit + size;
  fclose (fichier);
  //printf("%d\n",size);
  return 1;
}

int md5(char *buffer )
{
  MD5_CTX contexte;
  MD5_Init (&contexte);
  int size =strlen(buffer);
  printf("%d \n",size);
  MD5_Update (&contexte, buffer, size);// Digestion du morceau
  MD5_Final (resume_md5, &contexte);
  printf("Le résumé MD5 du mdp vaut:");
  for(int i = 0; i < MD5_DIGEST_LENGTH; i++) printf("%02x", resume_md5[i]);
  printf("\n");
  return 1;
}
 


void RotWord( uchar * tmp)
{
  uchar inter;
  inter = tmp[0];
  tmp[0]=tmp[1];
  tmp[1]=tmp[2];
  tmp[2]=tmp[3];
  tmp[3]=inter;
}

void SubWord ( uchar * tmp)
{
  int i;
  for(i=0;i<4;i++)
  {
    tmp[i]=SBox[tmp[i]];
  }
}

void affiche_la_clef(uchar *clef, int longueur)
{
  int i;
  for (i=0; i<longueur; i++) { printf ("%02X ", clef[i] & 255); }
  printf("\n");
}

void calcule_la_clef_etendue(uchar *K, int long_K, uchar *W, int long_W, int Nr, int Nk)
{
  int i,j;
  uchar tmp[4];

  for(i=0; i<long_W; i++)
  {
    W[i] = 0x00;
  }
  // À compléter
  for(i=0;i<long_K;i++)
  {
    W[i]=K[i];
  }
      
  for(i=long_K;i< 4*(4*(Nr+1));i++)
  {
    for(j=0;j<4;j++)
    {
      tmp[j] = W[i-4-j];
    }
    if( i % (long_K) == 0)
    {
      RotWord(tmp);
      SubWord(tmp);
      tmp[0] = tmp[0] ^ Rcon[i/(4*Nk)];
    }
    else if ((Nk > 6) && (i % (4*Nk) == 16))
    {
      SubWord(tmp);
    }

    for(j=0;j<4;j++)
    {
      tmp[j] = W[(i+j) - (4*Nk)] ^ tmp[j];
      W[j+i] = tmp[j];      
    }
  }
   
}

/* Pour compiler:
  $ make
  gcc aes.c -o aes -lm -std=c99
  $ ./aes
*/

