#include "compressor.hh"

int32_t CompressorChain::in_len_max( ) const { return _first_compressor.in_len_max()>>1; }

int32_t CompressorChain::out_len_max( int32_t in_len ) const
{
  // Chain compressor to find the maximum possible and add 5 bytes for header.
  return _second_compressor.out_len_max( _first_compressor.out_len_max(in_len) ) + 5;
}

int32_t CompressorChain::compress( const uint8_t *in, int32_t in_len, uint8_t *out ) const
{
   if( (in_len == 0) || (in_len > in_len_max()) ) return -1;

   // First compressor call. Output in a temporary buffer.
   int32_t temp_buffer_max = _first_compressor.out_len_max(in_len);
   uint8_t *temp_buffer = new uint8_t[temp_buffer_max];

   int32_t temp_buffer_real_len = _first_compressor.compress(in,in_len,&temp_buffer[0]);
   if( temp_buffer_real_len <= 0 ) { delete [] temp_buffer; return -1; }

   // Serialize temporary buffer length to the output.
   int32_t len_len = write_compact_32((uint32_t)temp_buffer_real_len, out);

   // Write second compression result into final output.
   int32_t second_len = _second_compressor.compress(&temp_buffer[0],temp_buffer_real_len,&out[len_len]);

   delete[] temp_buffer;
   return (second_len <= 0)? -1 : len_len+second_len;
}

int32_t CompressorChain::decompress( const uint8_t *in, int32_t in_len, uint8_t *out, int32_t out_len ) const
{
   if( in_len == 0 ) return -1;

   // Read temporary buffer length.
   int32_t temp_buffer_real_len;
   int32_t len_len = read_compact_32(in,(uint32_t *)&temp_buffer_real_len);

   // First secompression using second decompressot done into temporary buffer.
   uint8_t *temp_buffer = new uint8_t[temp_buffer_real_len];
   int32_t temp_uncomp_len = _second_compressor.decompress(&in[len_len],in_len-len_len,temp_buffer,temp_buffer_real_len);

   if( temp_uncomp_len != temp_buffer_real_len ) {
     delete[] temp_buffer;
     return -1;
   }

   // Second decompression using first decompressor done in final output.
   int32_t final_uncomp_len = _first_compressor.decompress(temp_buffer,temp_uncomp_len,out,out_len);
   delete[] temp_buffer;
   return (final_uncomp_len <= 0)? -1 : final_uncomp_len;
}

