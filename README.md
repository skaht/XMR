The Makefile works on a Mac OSX platform. Tweaks might need to be made for a
few compiler flags for your UNIX platform.  A **make scratch** will download
monero and boost packages, compile them, and build the six standalone commands
below.  The Makefile uses tcsh shell commands.  Similarly, the BUILD-boost
script called by the makefile builds the boost package used by Monero.

The list of package dependencies below is a work-in-progress and is not complete:

```
1) curl
2) ???
```


1% ./bytes_to_words -h

```
Usage: 
   ./bytes_to_words [ --help | -h ]
   ./bytes_to_words 64_digit_hexadecimal_number
   stdout | ./bytes_to_words
```


2% ./inverse_mnemonics -h

```
Usage: 
   ./inverse_mnemonics [ --help | -h ]
   ./inverse_mnemonics space_separated_list_of_25_Electrum_seed_words
   stdout | ./inverse_mnemonics
```


3% ./kec256 -h

```
Usage: 
   ./kec256 [ --help | -h ]
   ./kec256 64_digit_hexadecimal_number
   stdout | ./kec256
```


4% ./sc_reduce32 -h

```
Usage: 
   ./sc_reduce32 [ --help | -h ]
   ./sc_reduce32 64_digit_hexadecimal_number
   stdout | ./sc_reduce32
```


5% ./secret_key_to_public_key -h

```
Usage: 
   ./secret_key_to_public_key [ --help | -h ]
   ./secret_key_to_public_key 64_digit_hexadecimal_number
   stdout | ./secret_key_to_public_key
```


6% ./xmr -h

```
Usage: 
   ./xmr [ --help | -h ]
   ./xmr 64_digit_hexadecimal_number
   stdout | ./xmr
```


Examples:

% echo "explain olympic caught soccer ethics retire outdoor giant deposit legal quarter cupboard radar silent palm ecology scrap adapt install bone warm clog fantasy language" | bx mnemonic-to-seed | bx hd-new | bx hd-private -d -i 47 | bx hd-private -d -i 128 | bx hd-private -d -i 0 | bx hd-to-ec | ./xmr
```
    Seed                 : f9a0e73d3cd533368f75ff63cbd97b2100beffbc339cdfa5c203c1a022d9cf11
    Private Spend Key    : 0ccdf1e0217221deb8d807c1ecdf9c0c00beffbc339cdfa5c203c1a022d9cf01
    Private View Key     : f303de33534d6a9e46497cf177e12b7bdfaf1405b2a03b5a7074a74b0946a805
    Public Spend Key     : 2794fe656a521e21e4135aa13381b42cbeb180e653deda210f2039ca1009d110
    Public View Key      : d76344d2c5467758f0bcbf03925bc8bf4b659e163ec68c342c7ba94b9679a125
    Monero Address       : 4387BkqvmwB6fnVf4kwNUb8V5jJbQtWNV6XiSiSw1kXz3pPAy9ooZe6FsqKYLo4b19YzoCJQPxWdy9j9kStsRLLg5B8R4Ke
    Electrum Seed Words  : dehydrate opened lilac elapse subtly prying swept ruby liar veteran wife afloat strained camp tugs pager dual tomorrow aimless boxes saucepan invoke utensils vapidly lilac
```

% echo f9a0e73d3cd533368f75ff63cbd97b2100beffbc339cdfa5c203c1a022d9cf11 | ./xmr
```
    Seed                 : f9a0e73d3cd533368f75ff63cbd97b2100beffbc339cdfa5c203c1a022d9cf11
    Private Spend Key    : 0ccdf1e0217221deb8d807c1ecdf9c0c00beffbc339cdfa5c203c1a022d9cf01
    Private View Key     : f303de33534d6a9e46497cf177e12b7bdfaf1405b2a03b5a7074a74b0946a805
    Public Spend Key     : 2794fe656a521e21e4135aa13381b42cbeb180e653deda210f2039ca1009d110
    Public View Key      : d76344d2c5467758f0bcbf03925bc8bf4b659e163ec68c342c7ba94b9679a125
    Monero Address       : 4387BkqvmwB6fnVf4kwNUb8V5jJbQtWNV6XiSiSw1kXz3pPAy9ooZe6FsqKYLo4b19YzoCJQPxWdy9j9kStsRLLg5B8R4Ke
    Electrum Seed Words  : dehydrate opened lilac elapse subtly prying swept ruby liar veteran wife afloat strained camp tugs pager dual tomorrow aimless boxes saucepan invoke utensils vapidly lilac
```

% ./sc_reduce32 f9a0e73d3cd533368f75ff63cbd97b2100beffbc339cdfa5c203c1a022d9cf11
```
0ccdf1e0217221deb8d807c1ecdf9c0c00beffbc339cdfa5c203c1a022d9cf01
```

% ./kec256 0ccdf1e0217221deb8d807c1ecdf9c0c00beffbc339cdfa5c203c1a022d9cf01
```
fcc659eca955591729400f38c6917e8ae0af1405b2a03b5a7074a74b0946a8d5
```

% ./sc_reduce32 fcc659eca955591729400f38c6917e8ae0af1405b2a03b5a7074a74b0946a8d5
```
f303de33534d6a9e46497cf177e12b7bdfaf1405b2a03b5a7074a74b0946a805
```

% ./secret_key_to_public_key f303de33534d6a9e46497cf177e12b7bdfaf1405b2a03b5a7074a74b0946a805
```
d76344d2c5467758f0bcbf03925bc8bf4b659e163ec68c342c7ba94b9679a125
```

% ./bytes_to_words 0ccdf1e0217221deb8d807c1ecdf9c0c00beffbc339cdfa5c203c1a022d9cf01
```
dehydrate opened lilac elapse subtly prying swept ruby liar veteran wife afloat strained camp tugs pager dual tomorrow aimless boxes saucepan invoke utensils vapidly lilac
```

% ./inverse_mnemonics dehydrate opened lilac elapse subtly prying swept ruby liar veteran wife afloat strained camp tugs pager dual tomorrow aimless boxes saucepan invoke utensils vapidly lilac
```
0ccdf1e0217221deb8d807c1ecdf9c0c00beffbc339cdfa5c203c1a022d9cf01
```

Contrast results above to:

1) [https://xmr.llcoins.net/addresstests.html](https://xmr.llcoins.net/addresstests.html)

2) [https://xmr.llcoins.net/](https://xmr.llcoins.net/)
