/**
 * \file md5.h
 *
 * \brief MD5 message digest algorithm (hash function)
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#include <stddef.h>
#include <stdint.h>

typedef struct
{
    uint32_t total[2];          /*!< number of bytes processed  */
    uint32_t state[4];          /*!< intermediate digest state  */
    unsigned char buffer[64];   /*!< data block being processed */
}
mbedtls_md5_context;


void mbedtls_md5_init( mbedtls_md5_context *ctx );


void mbedtls_md5_free( mbedtls_md5_context *ctx );


void mbedtls_md5_clone( mbedtls_md5_context *dst,
                        const mbedtls_md5_context *src );


void mbedtls_md5_starts( mbedtls_md5_context *ctx );


void mbedtls_md5_update( mbedtls_md5_context *ctx, const unsigned char *input, size_t ilen );


void mbedtls_md5_finish( mbedtls_md5_context *ctx, unsigned char output[16] );

/* Internal use */
void mbedtls_md5_process( mbedtls_md5_context *ctx, const unsigned char data[64] );


void mbedtls_md5( const unsigned char *input, size_t ilen, unsigned char output[16] );