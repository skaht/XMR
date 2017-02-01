#include <iostream>
#include <string>
#include <regex>

#include <stdio.h>

#include "crypto.h"
#include "electrum-words.h"

using namespace std;

static void print256bits_as_hex( const unsigned char * );

//std::string          mnemonic_str { "ingested dolphin family snake icing tail ethics bevel awkward ablaze spying razor object vowels rotate yawning buying jargon yacht imitate unhappy truth toolbox august spying" };

int main( int argc, char *argv[] )
{
  string             line;
  smatch             matches;

  std::string        mnemonic_str;
  std::string        language { "English" };
  crypto::secret_key seed;
  
  if( argc == 1 ) // Assumes input is 13 or 25 Electrum words passed through stdin
  {
    regex    pattern{ R"(([a-zA-Z]+\s){24}([a-zA-Z]+))" };  // Regular expression for 25 Electrum words

    std::getline( std::cin, line );
    if( std::regex_search( line, matches, pattern ) )
        mnemonic_str.assign( matches[0] );
    else
    {
      cerr << "Error: executable \"" << argv[0] << "\" couldn't read 25 Electrum words from stdin successfully!!" << endl;
      return( 1 );
    }
  }
  else if( argc == 2 ) 
  {
    regex    pattern1{ R"(-h)" };      // Help
    regex    pattern2{ R"(--help)" };  // Help

    if( std::regex_search( (string)argv[1], matches, pattern1 ) ||
        std::regex_search( (string)argv[1], matches, pattern2 )    )   
    {   
      cout << "\nUsage: " << endl
           << "   " << argv[0] << " [ --help | -h ]" << endl
           << "   " << argv[0] << " space_separated_list_of_25_Electrum_seed_words" << endl
           << "   stdout | " << argv[0] << endl << endl;
      return( 0 );
    }   
    else
    {
      cerr << "Error: executable \"" << argv[0] << "\" couldn't read input arguments successfully!!";
      cout << "\nUsage: " << endl
           << "   " << argv[0] << " [ --help | -h ]" << endl
           << "   " << argv[0] << " space_separated_list_of_25_Electrum_seed_words" << endl
           << "   stdout | " << argv[0] << endl << endl;
      return( 1 );
    }
  }
  else if( argc == 26 )
  {
    regex   pattern3{ R"(([a-zA-Z]+){1})" };  // Regular expression for 1 Electrum words
    string  concat;

    for( int ii = 1 ; ii < 26 ; ii++ )
    {
      if( std::regex_search( (string)argv[ii], matches, pattern3 ) )
          mnemonic_str = mnemonic_str + " " + argv[ii];
    }
  }
  else
  {
    cerr << "Error: executable \"" << argv[0] << "\" couldn't read input arguments successfully!!";
    cout << "\nUsage: " << endl
         << "   " << argv[0] << " [ --help | -h ]" << endl
         << "   " << argv[0] << " space_separated_list_of_25_Electrum_seed_words" << endl
         << "   stdout | " << argv[0] << endl << endl;
    return( 1 );
  }

  if( !crypto::ElectrumWords::words_to_bytes( mnemonic_str, seed, language ) )
  {
     cerr << "\nCan't create the mnemonic for the private spend key: " << endl;
     exit( 1 );
  }

  print256bits_as_hex( (const unsigned char *)&seed.data[0] );
  cout << endl;
  
  return( 0 );
}

void print256bits_as_hex( const unsigned char *key )
{
  for( int ii = 0 ; ii < 32 ; ii += 8 ) 
    printf( "%02x%02x%02x%02x%02x%02x%02x%02x", 
             key[ii],   key[ii+1], key[ii+2], key[ii+3], 
             key[ii+4], key[ii+5], key[ii+6], key[ii+7] );
}
