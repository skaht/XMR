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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>  // defines: uint64_t, uint8_t

#include "crypto.h"  // defines: assert

#include "xmr_common.h"


void xmr_encode_varint(uint64_t value, uint8_t **ptr, size_t *incount)
{
  uint8_t *p = *ptr;
  size_t   count = 1;

  while( value >= 0x80 )
  {   
     *p++ = ((uint8_t)(value & 0x7F)) | 0x80;
      value >>= 7;
    ++count;
  }   

  *p++      = ((uint8_t)value) & 0x7F;
  *ptr     += count;
  *incount += count;
}


// From https://github.com/NoodleDoodleNoodleDoodleNoodleDoodleNoo/trezor-xmr/blob/master/shared/stream.c
#define B58_FULL_BLOCK_SIZE          8U
#define B58_ENCODED_FULL_BLOCK_SIZE 11U
#define B58_ALPHABET_SIZE           58U
static const char b58_alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const size_t b58_encoded_block_sizes[] = {0, 2, 3, 5, 6, 7, 9, 10, 11};


// From https://github.com/monero-project/monero/blob/master/src/common/base58.cpp
// From https://github.com/NoodleDoodleNoodleDoodleNoodleDoodleNoo/trezor-xmr/blob/master/shared/stream.c
static uint64_t uint_8be_to_64(const uint8_t *data, size_t size)
{
        assert(1 <= size && size <= sizeof(uint64_t));

        uint64_t res = 0;
        switch (9 - size)
        {   
        case 1:            res |= *data++;
        case 2: res <<= 8; res |= *data++;
        case 3: res <<= 8; res |= *data++;
        case 4: res <<= 8; res |= *data++;
        case 5: res <<= 8; res |= *data++;
        case 6: res <<= 8; res |= *data++;
        case 7: res <<= 8; res |= *data++;
        case 8: res <<= 8; res |= *data; break;
        default: assert(false);
        }   

        return res;
}


// From https://github.com/NoodleDoodleNoodleDoodleNoodleDoodleNoo/trezor-xmr/blob/master/shared/stream.c
static void b58_encode_block(const uint8_t *block, size_t size, char *res)
{
        assert(1 <= size && size <= B58_FULL_BLOCK_SIZE);
        uint64_t num = uint_8be_to_64((uint8_t *) block, size);
        size_t i = b58_encoded_block_sizes[size] - 1;
        while (0 < num)
        {
                uint64_t remainder = num % B58_ALPHABET_SIZE;
                num /= B58_ALPHABET_SIZE;
                res[i] = b58_alphabet[remainder];
                --i;

        }
}


// From https://github.com/NoodleDoodleNoodleDoodleNoodleDoodleNoo/trezor-xmr/blob/master/shared/stream.c
static void b58_encode(const uint8_t *data, size_t datalen, char *encoded)
{
        size_t block_count = datalen / B58_FULL_BLOCK_SIZE;
        size_t last_block_size = datalen % B58_FULL_BLOCK_SIZE;
        size_t res_size = block_count * B58_ENCODED_FULL_BLOCK_SIZE + b58_encoded_block_sizes[last_block_size];

        memset(encoded, b58_alphabet[0], res_size);

        for (size_t i = 0; i < block_count; i++)
        {
                b58_encode_block(data + i * B58_FULL_BLOCK_SIZE, B58_FULL_BLOCK_SIZE,
                                &encoded[i * B58_ENCODED_FULL_BLOCK_SIZE]);

        }

        if (0 < last_block_size)
        {
                b58_encode_block(data +  block_count * B58_FULL_BLOCK_SIZE, last_block_size,
                                &encoded[block_count * B58_ENCODED_FULL_BLOCK_SIZE]);
        }

        encoded[res_size] = '\0';
}


// From https://github.com/NoodleDoodleNoodleDoodleNoodleDoodleNoo/trezor-xmr/blob/master/shared/stream.h
#define XMR_TESTNET_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX 54U  // 0x36
#define XMR_TESTNET_PUBLIC_ADDRESS_BASE58_PREFIX            53U  // 0x35
#define XMR_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX         19U  // 0x13
#define XMR_PUBLIC_ADDRESS_BASE58_PREFIX                    18U  // 0x12
#define XMR_ENCRYPTED_PAYMENT_ID_SIZE                        8U
#define XMR_ADDRESS_CHECKSUM_SIZE                            4U


// From https://github.com/NoodleDoodleNoodleDoodleNoodleDoodleNoo/trezor-xmr/blob/master/shared/stream.c
bool xmr_get_b58_address(bool integrated, bool testnet, const xmr_address *address, const xmr_hash *payment_id, char *encoded_addr)
{
        uint8_t buffer[256];
        size_t len = 0;

        uint8_t tag;

        if(integrated)
                tag = testnet ? XMR_TESTNET_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX : XMR_PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
        else
                tag = testnet ? XMR_TESTNET_PUBLIC_ADDRESS_BASE58_PREFIX :            XMR_PUBLIC_ADDRESS_BASE58_PREFIX;

        uint8_t *p = buffer;
        xmr_encode_varint(tag, &p, &len);

        memcpy(buffer + len, address->spendkey.data, sizeof(address->spendkey.data));
        len += sizeof(address->spendkey.data);
        memcpy(buffer + len, address->viewkey.data, sizeof(address->viewkey.data));
        len += sizeof(address->viewkey.data);

        if(integrated)
        {
                memcpy(buffer + len, payment_id, XMR_ENCRYPTED_PAYMENT_ID_SIZE);
                len += XMR_ENCRYPTED_PAYMENT_ID_SIZE;
        }

        xmr_hash checksum;
        keccak(buffer, len, checksum.data, sizeof(checksum.data));
        memcpy(buffer + len, checksum.data, XMR_ADDRESS_CHECKSUM_SIZE);
        len += XMR_ADDRESS_CHECKSUM_SIZE;
        b58_encode(buffer, len, encoded_addr);

        return true;
}


/* Common functions */

// From https://github.com/monero-project/monero/blob/master/src/crypto/crypto-ops.c
static uint64_t load_3(const unsigned char *in) 
{
  uint64_t result;
  result = (uint64_t) in[0];
  result |= ((uint64_t) in[1]) << 8;
  result |= ((uint64_t) in[2]) << 16;
  return result;
}

// From https://github.com/monero-project/monero/blob/master/src/crypto/crypto-ops.c
static uint64_t load_4(const unsigned char *in)
{
  uint64_t result;
  result = (uint64_t) in[0];
  result |= ((uint64_t) in[1]) << 8;
  result |= ((uint64_t) in[2]) << 16;
  result |= ((uint64_t) in[3]) << 24;
  return result;
}

// From https://github.com/monero-project/monero/blob/master/src/crypto/crypto-ops.c
void sc_reduce32(unsigned char *s) 
{
  int64_t s0 = 2097151 & load_3(s);
  int64_t s1 = 2097151 & (load_4(s + 2) >> 5);
  int64_t s2 = 2097151 & (load_3(s + 5) >> 2);
  int64_t s3 = 2097151 & (load_4(s + 7) >> 7);
  int64_t s4 = 2097151 & (load_4(s + 10) >> 4);
  int64_t s5 = 2097151 & (load_3(s + 13) >> 1);
  int64_t s6 = 2097151 & (load_4(s + 15) >> 6);
  int64_t s7 = 2097151 & (load_3(s + 18) >> 3);
  int64_t s8 = 2097151 & load_3(s + 21); 
  int64_t s9 = 2097151 & (load_4(s + 23) >> 5);
  int64_t s10 = 2097151 & (load_3(s + 26) >> 2);
  int64_t s11 = (load_4(s + 28) >> 7);
  int64_t s12 = 0; 
  int64_t carry0;
  int64_t carry1;
  int64_t carry2;
  int64_t carry3;
  int64_t carry4;
  int64_t carry5;
  int64_t carry6;
  int64_t carry7;
  int64_t carry8;
  int64_t carry9;
  int64_t carry10;
  int64_t carry11;

  carry0 = (s0 + (1<<20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
  carry2 = (s2 + (1<<20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
  carry4 = (s4 + (1<<20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
  carry6 = (s6 + (1<<20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
  carry8 = (s8 + (1<<20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
  carry10 = (s10 + (1<<20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

  carry1 = (s1 + (1<<20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
  carry3 = (s3 + (1<<20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
  carry5 = (s5 + (1<<20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
  carry7 = (s7 + (1<<20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
  carry9 = (s9 + (1<<20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
  carry11 = (s11 + (1<<20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;
  s12 = 0;

  carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
  carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
  carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
  carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
  carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
  carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
  carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
  carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
  carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
  carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
  carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
  carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

  s0 += s12 * 666643;
  s1 += s12 * 470296;
  s2 += s12 * 654183;
  s3 -= s12 * 997805;
  s4 += s12 * 136657;
  s5 -= s12 * 683901;

  carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
  carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
  carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
  carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
  carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
  carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
  carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
  carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
  carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
  carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
  carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

  s[0] = s0 >> 0;
  s[1] = s0 >> 8;
  s[2] = (s0 >> 16) | (s1 << 5);
  s[3] = s1 >> 3;
  s[4] = s1 >> 11;
  s[5] = (s1 >> 19) | (s2 << 2);
  s[6] = s2 >> 6;
  s[7] = (s2 >> 14) | (s3 << 7);
  s[8] = s3 >> 1;
  s[9] = s3 >> 9;
  s[10] = (s3 >> 17) | (s4 << 4);
  s[11] = s4 >> 4;
  s[12] = s4 >> 12;
  s[13] = (s4 >> 20) | (s5 << 1);
  s[14] = s5 >> 7;
  s[15] = (s5 >> 15) | (s6 << 6);
  s[16] = s6 >> 2;
  s[17] = s6 >> 10;
  s[18] = (s6 >> 18) | (s7 << 3);
  s[19] = s7 >> 5;
  s[20] = s7 >> 13;
  s[21] = s8 >> 0;
  s[22] = s8 >> 8;
  s[23] = (s8 >> 16) | (s9 << 5);
  s[24] = s9 >> 3;
  s[25] = s9 >> 11;
  s[26] = (s9 >> 19) | (s10 << 2);
  s[27] = s10 >> 6;
  s[28] = (s10 >> 14) | (s11 << 7);
  s[29] = s11 >> 1;
  s[30] = s11 >> 9;
  s[31] = s11 >> 17;
}
