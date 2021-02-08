/**
  *
  *  Portions COPYRIGHT 2016 STMicroelectronics
  *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
  *
  ******************************************************************************
  * @file    ssl_server.c 
  * @author  MCD Application Team
  * @brief   SSL server application 
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT(c) 2017 STMicroelectronics</center></h2>
  *
  * Redistribution and use in source and binary forms, with or without modification,
  * are permitted provided that the following conditions are met:
  *   1. Redistributions of source code must retain the above copyright notice,
  *      this list of conditions and the following disclaimer.
  *   2. Redistributions in binary form must reproduce the above copyright notice,
  *      this list of conditions and the following disclaimer in the documentation
  *      and/or other materials provided with the distribution.
  *   3. Neither the name of STMicroelectronics nor the names of its contributors
  *      may be used to endorse or promote products derived from this software
  *      without specific prior written permission.
  *
  * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  ******************************************************************************
  */ 

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "main.h"
#include "cmsis_os.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_time       time
#define mbedtls_time_t     time_t 
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#endif
#define read_size 16384 //(Bytes) //1024
#include <stdlib.h>
#include <string.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/sha256.h"
#include "MY_FLASH.h"
#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#define Protection 1
static mbedtls_net_context listen_fd, client_fd;
static uint8_t buf[1024];
static uint8_t buf_1[32];
static const uint8_t *pers = (uint8_t *)("ssl_server");
static osThreadId LedThreadId;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_x509_crt srvcert;
mbedtls_pk_context pkey;
//static unsigned char password_sha[] ={0xcf,0x7b,0x02,0x03,0xd8,0x1d,0x7c,0xf4,0x52,0x54,0xb7,0x06,0x4c,0x8a,0x7f,0x75,0xc8,0x08,0x1e,0x06,0xf0,0x96,0xb4,0x14,0x1c,0xf6,0xd5,0x48,0xc3,0x29,0x6a,0x47};
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

void LED_Thread(void const *argument)
{
	while (1)
	{
	  BSP_LED_Toggle(LED1);
	  osDelay(200);
	}
}

void SSL_Server(void const *argument)
{
  mbedtls_printf( "  Startup Time =%d\n", (int)HAL_GetTick());
  int ret, len;
  int index_ = 0;
  const unsigned char *HashBuffer_1;
  MY_FLASH_SetSectorAddrs(0, 0x08000000);
  static unsigned char rData[read_size];
  static unsigned char wData[6]= {0x55,0x55,0x85,0x55,0x45,0x55};

  UNUSED(argument);
 
#ifdef MBEDTLS_MEMORY_BUFFER_ALLOC_C
  mbedtls_memory_buffer_alloc_init(memory_buf, sizeof(memory_buf));
#endif
  mbedtls_net_init( &listen_fd );
  mbedtls_net_init( &client_fd );
  
  mbedtls_ssl_init( &ssl );
  mbedtls_ssl_config_init( &conf );
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_init( &cache );
#endif
  mbedtls_x509_crt_init( &srvcert );
  mbedtls_pk_init( &pkey );
  mbedtls_entropy_init( &entropy );
  mbedtls_ctr_drbg_init( &ctr_drbg );

  /* Init the LED_Thread to know whether the application is running or not */
  osThreadDef(LedThread, LED_Thread, osPriorityLow, 0, configMINIMAL_STACK_SIZE);
  LedThreadId = osThreadCreate (osThread(LedThread), NULL);
  
#if defined(MBEDTLS_DEBUG_C)
  mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

  /*
   * 1. Load the certificates and private RSA key
   */
 // mbedtls_printf( "\n  . Loading the server cert. and key..." );


  /*
   * This demonstration program uses embedded test certificates.
   * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
   * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
   */
  ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_srv_crt, mbedtls_test_srv_crt_len );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
    goto exit;
  }

  ret = mbedtls_x509_crt_parse( &srvcert, (const unsigned char *) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
    goto exit;
  }

  ret =  mbedtls_pk_parse_key( &pkey, (const unsigned char *) mbedtls_test_srv_key, mbedtls_test_srv_key_len, NULL, 0 );
  if( ret != 0 )
  {
    mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
    goto exit;
  }

  //mbedtls_printf( " ok\n" );

  /*
   * 2. Setup the listening TCP socket
   */
  //mbedtls_printf( "  . Bind on https://localhost:4433/ ..." );

  if((ret = mbedtls_net_bind(&listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP )) != 0)
  {
    mbedtls_printf( " failed\n  ! mbedtls_net_bind returned %d\n\n", ret );
    goto exit;
  }

  //mbedtls_printf( " ok\n" );

  /*
   * 3. Seed the RNG
   */
  //mbedtls_printf( "  . Seeding the random number generator..." );

  if((ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, strlen( (char *)pers))) != 0)
  {
    mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    goto exit;
  }

  //mbedtls_printf( " ok\n" );

  /*
   * 4. Setup stuff
   */
 // mbedtls_printf( "  . Setting up the SSL data...." );

  if( ( ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
  {
    mbedtls_printf( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
    goto exit;
  }

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_conf_session_cache(&conf, &cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif

  mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
  if( ( ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey ) ) != 0)
  {
    mbedtls_printf( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
    goto exit;
  }

  if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
  {
    mbedtls_printf( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
    goto exit;
  }

  //mbedtls_printf( " ok\n" );

reset:
#ifdef MBEDTLS_ERROR_C
  if( ret != 0 )
  {
    uint8_t error_buf[100];
    mbedtls_strerror( ret, (char *)error_buf, 100 );
    mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf );
  }
#endif

  mbedtls_net_free( &client_fd );

  mbedtls_ssl_session_reset( &ssl );

  /*
   * 5. Wait until a client connects
   */
 // mbedtls_printf( "  . Waiting for a remote connection ...\n" );

  if((ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL)) != 0)
  {
    mbedtls_printf( "  => connection failed\n  ! mbedtls_net_accept returned %d\n\n", ret );
    goto exit;
  }

  mbedtls_ssl_set_bio( &ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

 // mbedtls_printf( "  => connection ok\n" );


  /*
   * 6. Handshake
   */
  //mbedtls_printf( "  . Performing the SSL/TLS handshake..." );

  while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
  {
    if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
    {
      mbedtls_printf( " failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret );
      goto reset;
    }
  }

  //mbedtls_printf( " ok\n" );

  /*
   * 7. Read Password*/
  //mbedtls_printf( "  < Read from client:" );
   static unsigned char PA[7];
   const unsigned char *HashBuffer;
   unsigned char sha256_password[32];
	uint8_t result;
	char password_sha[32] ={0xcf,0x7b,0x02,0x03,0xd8,0x1d,0x7c,0xf4,0x52,0x54,0xb7,0x06,0x4c,0x8a,0x7f,0x75,0xc8,0x08,0x1e,0x06,0xf0,0x96,0xb4,0x14,0x1c,0xf6,0xd5,0x48,0xc3,0x29,0x6a,0x47};
   do
   {
     len = sizeof( buf ) - 1;
     memset( buf, 0, sizeof( buf ) );
     ret = mbedtls_ssl_read( &ssl, buf, len );
     memcpy(PA, (char *)buf, 7);
     HashBuffer = PA;
     mbedtls_sha256(HashBuffer, 7, sha256_password, 0);

     //result = strcmp((char *)sha256_password,password_sha);
     if (memcmp(sha256_password, password_sha, sizeof(password_sha) / sizeof(password_sha[0])) != 0){
    	//Do something if password incorrect
     }
     else{
    	 //Do something if password is correct
     }

     if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
 	{
       continue;
     }
     if( ret <= 0 )
     {
       switch( ret )
       {
         case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
           mbedtls_printf( " connection was closed gracefully\n" );
           break;

         case MBEDTLS_ERR_NET_CONN_RESET:
           mbedtls_printf( " connection was reset by peer\n" );
           break;

         default:
           mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
           break;
       }

       break;
     }

     len = ret;
     //mbedtls_printf( " %d bytes read\n%s", len, (char *) buf );

     if( ret > 0 )
 	{
       break;
 	}
   } while(1);

#if (Protection == 1)

//Measuring Hashing a Block [Start]
  // mbedtls_printf( "  Delay Before =%d\n", (int)HAL_GetTick());

  /* Reading and Hashing */

	  MY_FLASH_ReadN(index_,rData,read_size,DATA_TYPE_8);
	  HashBuffer_1 = rData;
	 mbedtls_sha256(HashBuffer_1, read_size, sha256_out, 0);
	 index_=index_+read_size;

	 if(index_ >= 0xFA360  ){

		 BSP_LED_Toggle(LED3);

		 index_ =0;
	 }
	 //Measuring Hashing a Block [End]
// mbedtls_printf( " Delay After =%d\n", (int)HAL_GetTick());

	    /* End */
  //mbedtls_printf( "  > Write to client:" );

  /* Write to client The Hashed block*/
len = sprintf( (char *) buf, (char *) sha256_out, mbedtls_ssl_get_ciphersuite( &ssl ) );
//  mbedtls_printf((char *)buf);
while( ( ret = mbedtls_ssl_write( &ssl, buf, 32 ) ) <= 0 )
{
  if( ret == MBEDTLS_ERR_NET_CONN_RESET )
  {
    mbedtls_printf( " failed\n  ! peer closed the connection\n\n" );
    goto reset;
  }
  if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
  {
    mbedtls_printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
    goto exit;
  }
}

  len = ret;
//mbedtls_printf( " %d bytes written\n%s", len, (char *) buf );
//mbedtls_printf( " %d Delay\n%s", HAL_GetTick());
//mbedtls_printf( "  . Closing the connection..." );

//Read status

   static unsigned char SA[1];
   //const unsigned char *HashBuffer;
	//uint8_t result_1;
	char XXX[1] = {0x41};
   do
   {
     len = sizeof( buf ) - 1;
     memset( buf, 0, sizeof( buf ) );
     ret = mbedtls_ssl_read( &ssl, buf, len );
     memcpy(SA, (char *)buf, 1);
     //HashBuffer = PA;
    // mbedtls_sha256(HashBuffer, 7, sha256_password, 0);

     //result = strcmp((char *)sha256_password,password_sha);
     if (memcmp(SA, XXX, sizeof(XXX) / sizeof(XXX[0])) != 0){
    	//Do something if password incorrect
    	 BSP_LED_Toggle(LED4);
    	 status =1;
     }
     else{
    	 //Do something if password is correct
    	 BSP_LED_Toggle(LED2);
     }

     if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
 	{
       continue;
     }
     if( ret <= 0 )
     {
       switch( ret )
       {
         case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
           mbedtls_printf( " connection was closed gracefully\n" );
           break;

         case MBEDTLS_ERR_NET_CONN_RESET:
           mbedtls_printf( " connection was reset by peer\n" );
           break;

         default:
           mbedtls_printf( " mbedtls_ssl_read returned -0x%x\n", -ret );
           break;
       }

       break;
     }

     len = ret;
     //mbedtls_printf( " %d bytes read\n%s", len, (char *) buf );

     if( ret > 0 )
 	{
       break;
 	}
   } while(1);

  while( ( ret = mbedtls_ssl_close_notify( &ssl ) ) < 0 )
  {
    if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
    {
      mbedtls_printf( " failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret );
      goto reset;
    }
  }
#endif
  //mbedtls_printf( " ok\n" );
  osDelay(500);
  ret = 0;
  //mbedtls_printf( "  End Time =%d\n", (int)HAL_GetTick());
  goto reset;

exit:
  mbedtls_net_free( &client_fd );
  mbedtls_net_free( &listen_fd );

  mbedtls_x509_crt_free( &srvcert );
  mbedtls_pk_free( &pkey );
  mbedtls_ssl_free( &ssl );
  mbedtls_ssl_config_free( &conf );
#if defined(MBEDTLS_SSL_CACHE_C)
  mbedtls_ssl_cache_free( &cache );
#endif
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );
  osThreadTerminate(LedThreadId);
}
