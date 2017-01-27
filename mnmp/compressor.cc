#include "compressor.hh"

int32_t write_compact_32( uint32_t value, uint8_t* out ) {
  // Write 7 bits at the time, starting with LSB bits.
  // Set the MSB of an output byte to indicate that at least
  // one other byte is needed for encoding this value.

  // TODO: Profile unrolling of the loop.
  int32_t nb_byte_written = 0;
  while( value > 0x7F ) {
    out[nb_byte_written++] = ((uint8_t)(value & 0x7F)) | 0x80;
    value >>= 7;
  }
  // Write last byte (or first if value <= 0x7f).
  // Notice at this point the MSB in the output byte
  // is always zero.
  out[nb_byte_written++] = (uint8_t)value;
  return nb_byte_written;
}

int32_t read_compact_32( const uint8_t* in, uint32_t *value ) {
  uint32_t tmp = 0;
  int32_t nb_byte_read = 1;

  // Read up to 5 bytes to rebuild the value.
  tmp |= in[0]&0x7F;
  if( in[0] & 0x80 ) {
    tmp |= (in[1]&0x7F)<<7;
    nb_byte_read++;
    if( in[1] & 0x80 ) {
      tmp |= (in[2]&0x7F)<<14;
      nb_byte_read++;
      if( in[2] & 0x80 ) {
        tmp |= (in[3]&0x7F)<<21;
        nb_byte_read++;
        if( in[3] & 0x80 ) {
          tmp |= (in[4]&0x7F)<<28;
          nb_byte_read++;
        }
      }
    }
  }

  *value = tmp;
  return nb_byte_read;
}

int32_t serial_size_compact_32( uint32_t value ) {
  if( value <=       127 ) return 1;
  if( value <=     16383 ) return 2;
  if( value <=   2097151 ) return 3;
  if( value <= 268435455 ) return 4;
  return 5;
}
