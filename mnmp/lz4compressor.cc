#include "compressor.hh"
#include "lz4.hh"

int32_t LZ4Compressor::in_len_max( ) const { return LZ4_MAX_INPUT_SIZE; }

int32_t LZ4Compressor::out_len_max( int32_t in_len ) const
{
  return LZ4_COMPRESSBOUND( in_len );
}

int32_t LZ4Compressor::compress( const uint8_t *in, int32_t in_len, uint8_t *out ) const
{
   if( (in_len == 0) || (in_len > LZ4_MAX_INPUT_SIZE) ) return -1;

   int32_t out_len = ::LZ4_compress( (const char *)in, (char *)out, in_len);

   return (out_len <= 0)? -1 : out_len;
}

int32_t LZ4Compressor::decompress( const uint8_t *in, int32_t in_len, uint8_t *out, int32_t out_len ) const
{
   if( in_len == 0 ) return -1;

   int32_t uncomp_len = ::LZ4_decompress_safe( (const char *)in, (char *)out, in_len, out_len );

   return (uncomp_len <= 0)? -1 : uncomp_len;
}

