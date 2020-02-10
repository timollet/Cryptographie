// -*- coding: utf-8 -*-

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>       // log, pow
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/md5.h>
typedef unsigned char uchar;
/*Declaration des fonctions utiles */

void chiffrer(void);
void dechiffrer(void);
void chiffrer_bloc_nul(void);
void dechiffrer_bloc_nul(void);
void afficher_le_bloc(uchar *M);
void SubBytes(void);
void Inv_SubBytes(void);
void ShiftRows(void);
void Inv_ShiftRows(void);
void MixColumns(void);
void Inv_MixColumns(void);
void AddRoundKey(int r);
void inverse_tab(void);
int pkcs5(char *nom_du_fichier);
int md5(char *buffer );
void RotWord( uchar * tmp);
void SubWord ( uchar * tmp);
void affiche_la_clef(uchar *clef, int longueur);
void calcule_la_clef_etendue(uchar *K, int long_K, uchar *W, int long_W, int Nr, int Nk);