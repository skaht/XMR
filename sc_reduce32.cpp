#include <iostream>
#include <string>
#include <regex>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>  // defines uint64_t

#include "xmr_common.h"

using namespace std;

static void print256bits_as_hex( const unsigned char* );
static void sprintkey( const char*, unsigned char* );

/**
const char *ED25519_SECRET_KEYS[] =
      {
        "26c76712d89d906e6672dafa614c42e5cb1caac8c6568e4d2493087db51f0d36",
        "fba7a5366b5cb98c2667a18783f5cf8f4f8d1a2ce939ad22a6e685edde85128d",
        "67e3aa7a14fac8445d15e45e38a523481a69ae35513c9e4143eb1c2196729a0e",
        "d51385942033a76dc17f089a59e6a5a7fe80d9c526ae8ddd8c3a506b99d3d0a6",
        "5c8eac469bb3f1b85bc7cd893f52dc42a9ab66f1b02b5ce6a68e9b175d3bb433",
        "eda433d483059b6d1ff8b7cfbd0fe406bfb23722c8f3c8252629284573b61b86",
        "4377c40431c30883c5fbd9bc92ae48d1ed8a47b81d13806beac5351739b5533d",
        "c6bbcce615839756aed2cc78b1de13884dd3618f48367a17597a16c1cd7a290b"
      };

const char *ED25519_REDUCED32_KEYS[] =
      {
        "5f4b86fb88745966e39bf311c65ea5a6cb1caac8c6568e4d2493087db51f0d06",
        "9308f74e984326cc7380e46f8e26d8e84e8d1a2ce939ad22a6e685edde85120d",
        "67e3aa7a14fac8445d15e45e38a523481a69ae35513c9e4143eb1c2196729a0e",
        "93cceaf21854effc615f5c3ca723f0d6fd80d9c526ae8ddd8c3a506b99d3d006",
        "9512cb2f4c8abab0d8f0e6a0a3643f04a9ab66f1b02b5ce6a68e9b175d3bb403",
        "850585ecb0ec07ad6c11fbb7c840ec5fbeb23722c8f3c8252629284573b61b06",
        "7cfbe2ede199d17a4225f3d3f6c0ab92ed8a47b81d13806beac5351739b5530d",
        "c6bbcce615839756aed2cc78b1de13884dd3618f48367a17597a16c1cd7a290b"
      };
**/

int main( int argc, char *argv[] )
{
  string   line;
  smatch   matches;
  regex    pattern{ R"([0-9a-fA-F]{64})" };  // ensures input is a 64 digit hexadecimal number

  unsigned char sk[32];

  if( argc == 1 ) // Assumes input is a 256-bit hexidecimal number passed by stdin
  {
    std::getline( std::cin, line );
    if( std::regex_search( line, matches, pattern ) ) 
    {   
      sprintkey( ((string)matches[0]).c_str(), (unsigned char*)&sk );
    }
    else
    {
      cerr << "Error: executable \"" << argv[0] << "\" couldn't read 64 digit hexadecimal number (No leading 0x) from stdin!! \n";
      return( 1 );
    }
  }
  else if( argc == 2 ) 
  {
    if( std::regex_search( (string)argv[1], matches, pattern ) ) 
    {   
      sprintkey( argv[1], (unsigned char *)&sk );  
    }   
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
        cerr << "Error: executable \"" << argv[0] << "\" couldn't read 64 digit hexadecimal number (No leading 0x) from stdin!!";
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

//Normalize initial Ed25519 secret key
  sc_reduce32( (unsigned char *)&sk );

  print256bits_as_hex( sk );
  cout << endl;
      
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
                 fprintf( stderr, "\n Error in sscan256bitkey() \n" );
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
