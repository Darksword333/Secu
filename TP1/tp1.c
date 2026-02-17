#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

typedef unsigned char decalage ;

#define CODE_ERREUR 255
decalage code ( char c ) {
  if ( isupper(c) ) return c - 'A' ;
  if ( islower(c) ) return c - 'a' ;
  /* erreur si ce n'est pas une lettre */
  return CODE_ERREUR ;
}

char minuscule ( decalage c ) {  return 'a' + ( c % 26 )  ; }
char majuscule ( decalage c ) { return 'A' + ( c % 26 )  ; }
decalage code_inverse ( decalage c ) { return ( 26 - c );  }
decalage chiffre_code ( decalage a , decalage b ) { return ( a+b ) % 26 ; }

char inverse_lettre ( char c ) { return minuscule ( code_inverse ( code ( c ) ) ) ; }
char * inverse_clef_old ( char * k )
{
  int len = strlen ( k ) ;
  char * clef = malloc ( len + 1 ) ;
  for ( int i = 0 ; i < len ; i++ )
    clef[i] = inverse_lettre ( k[i] ) ;
  clef[len] = '\0' ;
  printf ( "clé %s inverse de %s\n" , clef , k ) ;
  return clef ;
}

char * strmap ( char * s , char ( *f ) ( char ) )
{
  int len = strlen ( s ) ;
  char * res = malloc ( ( len + 1 ) * sizeof ( char ) ) ;
  for ( int i = 0 ; i < len ; i++ )
    res[i] = f ( s[i] ) ;
  res[len] = '\0' ;
  return res ;
}
char * inverse_clef ( char * k ) { return strmap ( k , & inverse_lettre ) ; }


char chiffre_lettre ( char a , char b ) 
{
  if ( isupper ( a ) ) return majuscule ( chiffre_code(code(a),code(b)) ) ;
  if ( islower ( a ) ) return minuscule ( chiffre_code(code(a),code(b)) ) ;
  return '_' ;
}
char * chiffre_chaine ( char * m , char * k )
{
  int j = 0 ;
  char encode ( char c )
  {
    if ( k[j] == 0 ) j = 0 ;
    if ( ! isalpha ( c ) ) return c ;
    return chiffre_lettre ( c , k[j++] ) ;
  }
  return strmap ( m , & encode ) ;
}


char * vigenere_chiffre ( char * m , char * k )
{
  printf ( "chiffrement avec la clef \"%s\"\n" , k ) ;
  return chiffre_chaine ( m , k ) ;
}
char * vigenere_dechiffre ( char * m , char * k )
{
  char * clef = inverse_clef ( k ) ;
  printf ( "Déchiffrement avec la clef \"%s\" inverse de \"%s\"\n" , clef , k ) ;
  char * res = chiffre_chaine ( m , clef ) ;
  free ( clef ) ;
  return res ;
}

char * cesar_chiffre ( char * m , char lettre )
{
  char clef[2] ;
  clef[0] = lettre  ;
  clef[1] = '\0' ;
  return chiffre_chaine ( m , clef ) ;
}
char * cesar_dechiffre ( char * m ,  char lettre )
{
  char clef[2] ;
  clef[0] = lettre ;
  clef[1] = '\0' ;
  char * clef_dechiffrement = inverse_clef ( clef ) ;
  char * res = chiffre_chaine ( m , clef_dechiffrement ) ;
  free ( clef_dechiffrement ) ;
  return res ;
}

int * calcule_frequences ( char * m )
{
  int * occurrences = malloc ( 26 * sizeof ( int ) ) ;
  for ( int i = 0 ; i < 26 ; i++ )
    occurrences[i] = 0 ;

  int len = strlen ( m ) ;
  for ( int i = 0 ; i <  len ; i++ )
    if ( code(m[i]) != CODE_ERREUR )
      occurrences[code(m[i])]++ ;
  return occurrences ;
}

/* à compléter: faire des analyses fréquentielles ou utiliser la force
   brute pour déchiffrer les textes donnés dans l'énoncé */

// Cryptanalyse
void test_cesar ( char * m ){
    char lettre = 'f'; // -> décalage de 5 par la droite ou 21 par la gauche
    char * toPrint = cesar_dechiffre(m, lettre);
    printf("%s\n", toPrint);
}

void test_vigenere ( char * m , int max ){

}

char * fileToChar(char *name){
  FILE *f = fopen(name, "r");
  if (f == NULL) {
      perror("Erreur");
      return "Error";
  }
  fseek(f, 0, SEEK_END);
  long longueur = ftell(f);
  rewind(f);
  char *contenu = malloc(longueur + 1);
  if (contenu == NULL) {
      perror("Erreur malloc");
      fclose(f);
      return "Error";
  }
  fread(contenu, 1, longueur, f);
  contenu[longueur] = '\0';
  fclose(f);
  return contenu;
}

int main(void){
  char *contenu;
  contenu = fileToChar("input/texte1.txt");
  test_cesar(contenu); // Exercice 1
  
  free(contenu);
  contenu = fileToChar("input/texte2.txt");

  //test_vigenere(contenu); // Exercice 2

  free(contenu);
  return EXIT_SUCCESS;
}