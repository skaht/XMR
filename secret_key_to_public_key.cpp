#include <iostream>
#include <string>
#include <regex>

#include "crypto.h"

#include <stdio.h>

using namespace std;

static void sprintkey( const char*, unsigned char* );
static void print256bits_as_hex( const unsigned char* );


int main( int argc, char *argv[] )
{
  string   line;
  smatch   matches;
  regex    pattern{ R"([0-9a-fA-F]{64})" };  // ensures input is a 64 digit hexadecimal number

  crypto::secret_key   sk;
  crypto::public_key   pk;

  if( argc == 1 ) //  Read from standard input
  {
    std::getline( std::cin, line );
    if( std::regex_search( line, matches, pattern ) ) 
    { 
      sprintkey( ((string)matches[0]).c_str(), (unsigned char *)&sk.data[0] );
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
      sprintkey( argv[1], (unsigned char *)&sk.data[0] ); 
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

  (void)crypto::secret_key_to_public_key( sk, pk );
  print256bits_as_hex( (unsigned char *)&pk.data[0] );
  cout << endl;

  return( 0 );
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
                 cerr << "Error in sprintkey() " << endl;
                 exit( 1 );
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


static void print256bits_as_hex( const unsigned char *data )
{
  for( int ii = 0 ; ii < 32 ; ii += 8 ) 
  {
    // C output function below is very reliable
    fprintf( stdout, "%02x%02x%02x%02x%02x%02x%02x%02x", 
             data[ii],   data[ii+1], data[ii+2], data[ii+3], 
             data[ii+4], data[ii+5], data[ii+6], data[ii+7] );

    /* C++ equivalent below is not yet reliable:
    std::cout << std::left << std::hex << std::cout.fill('0') << std::setw(2) 
              << (unsigned short)data[ii] 
              << (unsigned short)data[ii+1] 
              << (unsigned short)data[ii+2]
              << (unsigned short)data[ii+3] 
              << (unsigned short)data[ii+4] 
              << (unsigned short)data[ii+5] 
              << (unsigned short)data[ii+6] 
              << (unsigned short)data[ii+7];
    */
  }
}
