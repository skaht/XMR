#include <regex>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>  // defines: uint64_t, uint8_t

#include "crypto.h"
#include "electrum-words.h"

#include "xmr_common.h"

using namespace std;


static void print256bits_as_hex( const unsigned char* );
static void sprintkey( const char*, unsigned char* );

class my_crypto
{
   public:
     uint8_t             data[32];
     crypto::secret_key  sk;
     crypto::public_key  pk;

   public:
     my_crypto();
    ~my_crypto();

     crypto::secret_key secret_key();
     uint8_t*           public_key();
};

my_crypto::my_crypto()
   {
   }

crypto::secret_key my_crypto::secret_key()
   {
     memcpy( (void*)sk.data, (void*)data, sizeof( data ) );
     return( sk );
   }
uint8_t*  my_crypto::public_key()
   {
     return( (uint8_t*)pk.data );
   }

my_crypto::~my_crypto()
   {
   }


int main( int argc, char *argv[] )
{
  string   line;
  smatch   matches;
  regex    pattern{ R"([0-9a-fA-F]{64})" };  // ensures input is a 64 digit hexadecimal number

//crypto::secret_key   spend_sk, view_sk;
//crypto::public_key   spend_pk, view_pk;
  my_crypto            spend_sk, view_sk;
  my_crypto            spend_pk, view_pk;
  uint8_t              hash[32];
  
  if( argc == 1 )  //  Read from standard input
  {
    std::getline( std::cin, line );
    if( std::regex_search( line, matches, pattern ) )
      sprintkey( ((string)matches[0]).c_str(), spend_sk.data );
    else
    {
      cerr << "Error: executable \"" << argv[0] << "\" couldn't read a 64 digit hexadecimal number from stdin!! \n";
      return( 1 );
    }
  }
  else if( argc == 2 ) // Assumes second input is 256-bit hexidecimal number
  {
    if( std::regex_search( (string)argv[1], matches, pattern ) )
      sprintkey( argv[1], spend_sk.data );
    else
    {
      regex    pattern1{ R"(-h)" };      // Help
      regex    pattern2{ R"(--help)" };  // Help

      if( std::regex_search( (string)argv[1], matches, pattern1 ) ||
          std::regex_search( (string)argv[1], matches, pattern2 )    )
      {
        cout << "\nUsage: " << endl
             << "   " << argv[0] << " [ --help | -h ]" << endl
             << "   " << argv[0] << " 64_digit_hexadecimal_number" << endl
             << "   stdout | " << argv[0] << endl << endl;
        return( 0 );
      }
      else
      {
        cerr << "Error: executable \"" << argv[0] << "\" couldn't read input argument successfully!! \n";
        cout << "\nUsage: " << endl
             << "   " << argv[0] << " [ --help | -h ]" << endl
             << "   " << argv[0] << " 64_digit_hexadecimal_number" << endl
             << "   stdout | " << argv[0] << endl << endl;
        return( 1 );
      }
    }
  }
  else
  {
    cerr << "Error: executable \"" << argv[0] << "\" couldn't read input argument successfully!! \n";
    cout << "\nUsage: " << endl
         << "   " << argv[0] << " [ --help | -h ]" << endl
         << "   " << argv[0] << " 64_digit_hexadecimal_number" << endl
         << "   stdout | " << argv[0] << endl << endl;
    return( 1 );
  }
      
  printf( "    Seed                 : %s\n", ((string)matches[0]).c_str() );
  sc_reduce32( spend_sk.data );
  printf( "    Private Spend Key    : " ); print256bits_as_hex( spend_sk.data ); 

  if( keccak( spend_sk.data, sizeof( spend_sk.data ), hash, 256/8 ) != 0 )
  {
    cerr << "Error: executable \"" << argv[0] << "\" call to keccak() failed !!\n";
    return( 1 );
  }

  memcpy( (void*)view_sk.data, (void*)hash, sizeof( hash ) ); 
  sc_reduce32( view_sk.data );
  printf( "\n    Private View Key     : " ); print256bits_as_hex( view_sk.data ); 

  (void)crypto::secret_key_to_public_key( spend_sk.secret_key(), spend_pk.pk );
  (void)crypto::secret_key_to_public_key( view_sk.secret_key(),  view_pk.pk );

  printf( "\n    Public Spend Key     : " ); print256bits_as_hex( spend_pk.public_key() );
  printf( "\n    Public View Key      : " ); print256bits_as_hex( view_pk.public_key() );

  xmr_address address;
  char        encoded[256];
  string      language { "English" }, mnemonic_str;

  memcpy( (void*)&address.spendkey, (void*)&spend_pk.pk, sizeof( spend_pk.pk ) );
  memcpy( (void*)&address.viewkey,  (void*)&view_pk.pk,  sizeof( view_pk.pk )  ); 

  xmr_get_b58_address( false, false, &address, nullptr, encoded );
  printf( "\n    Monero Address       : %s", encoded );

  if( !crypto::ElectrumWords::bytes_to_words( spend_sk.sk, mnemonic_str, language ) ) 
  {
     cerr << "\nCan't create the mnemonic for the private spend key: " << endl;
     exit( 1 );
  }
  cout << "\n    Electrum Seed Words  : " << mnemonic_str << endl;

  return( 0 );
}


static void print256bits_as_hex( const unsigned char *key )
{
  for( int ii = 0 ; ii < 32 ; ii += 8 )
    printf( "%02x%02x%02x%02x%02x%02x%02x%02x", 
             key[ii],   key[ii+1], key[ii+2], key[ii+3], 
             key[ii+4], key[ii+5], key[ii+6], key[ii+7] );
}


static void sprintkey( const char *input, unsigned char *key )
{
  unsigned int hex, hex_even, hex_odd;

  if( input )
  {
    for( int ii = 0 ; input[ii] != 0 ; ii++ )
    {
      switch( tolower( input[ii] ) )
      {
        case '0': hex = 0;
                  break;
        case '1': hex = 1;
                  break;
        case '2': hex = 2;
                  break;
        case '3': hex = 3;
                  break;
        case '4': hex = 4;
                  break;
        case '5': hex = 5;
                  break;
        case '6': hex = 6;
                  break;
        case '7': hex = 7;
                  break;
        case '8': hex = 8;
                  break;
        case '9': hex = 9;
                  break;
        case 'a': hex = 10;
                  break;
        case 'b': hex = 11;
                  break;
        case 'c': hex = 12;
                  break;
        case 'd': hex = 13;
                  break;
        case 'e': hex = 14;
                  break;
        case 'f': hex = 15;
                  break;
        default:
                 cerr << "\n Error in sscan256bitkey() \n";
      }

      if( ii%2 )
      {
        hex_odd = hex;
        hex = (hex_even << 4) | hex_odd;
        key[ii/2] = hex; 
      }
      else
        hex_even = hex;
    }
  }
}
