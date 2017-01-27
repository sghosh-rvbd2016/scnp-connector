#include "compressor.hh"
#include <zlib.h>

int32_t ZLIBCompressor::in_len_max( ) const
{
  // Reduce the maximum supported length such that the mixing 
  // of signed/unsigned 32-bits integers does not cause problems.
  //
  // zlib requires that buffer length be at least 0.1% larger + 12 bytes;
  // 
  //   INT32_MAX - (INT32_MAX * 0.1%) = 0x7FDF3B63
  //   "rounded" to conservative 0x7E000000 which happens
  //   to be same as LZ4.
  return 0x7E000000;
}

int32_t ZLIBCompressor::out_len_max( int32_t in_len ) const
{
  return (int32_t)::compressBound( in_len );
}

int32_t ZLIBCompressor::compress( const uint8_t *in, int32_t in_len, 
                                  uint8_t *out ) const
{
   if( (in_len == 0) || (in_len > in_len_max()) ) return -1;

   uLongf destLen = (uLongf)::compressBound(in_len);

   int ret = ::compress( (Bytef *)out, &destLen, (const Bytef *)in, (uLongf)in_len );

   if( ret != Z_OK ) return -1; // Failure

   return (int32_t)destLen; // Success
}

int32_t ZLIBCompressor::decompress( const uint8_t *in, int32_t in_len,
                                    uint8_t *out, int32_t out_len ) const
{
   if( in_len == 0 ) return -1;

   uLongf destLen = (uLongf)out_len;
   int ret = ::uncompress( (Bytef *)out, &destLen,
                           (const Bytef *)in, (uLongf)in_len );

   if( ret != Z_OK ) return -1; // Failure

   return (int32_t)destLen; // Success
}
