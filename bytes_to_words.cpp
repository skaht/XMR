#include <iostream>
#include <string>
#include <regex>

#include "crypto.h"
#include "electrum-words.h"

using namespace std;

static void sprintkey( const char*, unsigned char* );


int main( int argc, char *argv[] )
{
  string   line;
  smatch   matches;
  regex    pattern{ R"([0-9a-fA-F]{64})" };  // ensures input is a 64 digit hexadecimal number

  crypto::secret_key   seed;
  string               language { "English" }, 
                       mnemonic_str;
  if( argc == 1 )
  {
    std::getline( std::cin, line );
    if( std::regex_search( line, matches, pattern ) )
        sprintkey( ((string)matches[0]).c_str(), (unsigned char *)&seed.data[0] );
    else
    {
      cerr << "Error: Usage:  stdout | " << argv[0] << " 64_digit_hexadecimal_number  (No leading 0x)" << endl;
      exit( 1 );
    }
  }
  else if( argc == 2 ) 
  {
    if( std::regex_search( (string)argv[1], matches, pattern ) )
        sprintkey( argv[1], (unsigned char *)&seed.data[0] );
    else
    {   
      regex    pattern1{ R"(--help)" };  // Help
      regex    pattern2{ R"(-h)" };      // Help

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

  if( !crypto::ElectrumWords::bytes_to_words( seed, mnemonic_str, language ) )
  {
     cerr << "Error: " << argv[0] << " Can't create the mnemonic for the private spend key: " << endl;
     exit( 1 );
  }
  cout << mnemonic_str << endl;
  
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
