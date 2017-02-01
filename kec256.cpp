#include <iostream>
#include <regex>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>  // defines: uint64_t, uint8_t

//#include "crypto.h"
#include "xmr_common.h"

using namespace std;

static void print256bits_as_hex( const unsigned char* );
static void sprintkey( const char*, unsigned char* );

// INPUT OPTIMIZED FOR 256-bit NUMBERS ONLY
// INPUT MUST BE A 64 HEXADECIMAL NUMBER

int main( int argc, char *argv[] )
{
  string   line;
  smatch   matches;
  regex    pattern{ R"([0-9a-fA-F]{64})" };  // input must be a 64 digit hexadecimal number

  char     hex[65];
  uint8_t  data[32];
  uint8_t  hash[32];

  if( argc == 1 )  //  Read from standard input
  {
    std::getline( std::cin, line );
    if( std::regex_search( line, matches, pattern ) )
    {
      sprintkey( ((string)matches[0]).c_str(), data );
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
      sprintkey( argv[1], data );  
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
      
  if( keccak( data, sizeof( data ), hash, 256/8 ) != 0 )
  {
    cerr << "Error: executable \"" << argv[0] << "\" call to keccak() failed !!\n";
    return( 1 );
  }
  print256bits_as_hex( hash ); 

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
