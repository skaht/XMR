// Copyright (c) 2014-2016, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are 
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#ifndef XMR_COMMON_
#define XMR_COMMON_

#define XMR_HASH_SIZE           32U 
#define XMR_KEY_SIZE_BYTES      32U 

typedef struct { uint8_t data[XMR_HASH_SIZE];      } xmr_hash;
typedef struct { uint8_t data[XMR_KEY_SIZE_BYTES]; } ec_point;
typedef ec_point xmr_pubkey;

typedef struct xmr_address_t
{
  xmr_pubkey spendkey;
  xmr_pubkey viewkey;
  uint32_t addr_type;
} xmr_address;


// From  https://github.com/monero-project/monero/blob/master/src/crypto/keccak.c
extern "C" int  keccak( const uint8_t*, size_t, uint8_t*, int );

// From  https://github.com/monero-project/monero/blob/master/src/crypto/crypto-ops.c
extern void     sc_reduce32( unsigned char* );

extern  bool xmr_get_b58_address( bool, bool, const xmr_address*, const xmr_hash*, char* );

#endif /* XMR_COMMON_  */
