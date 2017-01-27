#pragma once

#include <stdint.h>

// BlockCompressor process a block of bytes
// without maintaining states between calls.

class BlockCompressor {
public:
   virtual ~BlockCompressor() {}

   // Compression
   // ===========
   // On success, returns the number of bytes written to 'out'. 
   //
   // 'out' must be already allocated and must be able to handle
   // 'out_len_max()' bytes.
   // 
   // No more than 'out_len_max()' bytes are ever written to 'out'.
   //
   // 'in_len' exceeding 'in_len_max()' will result in an error.
   //
   // On errors, returns a negative value.
   //
   virtual int32_t out_len_max( int32_t in_len ) const = 0;
   virtual int32_t in_len_max() const = 0;

   virtual int32_t compress( const uint8_t *in, int32_t in_len, uint8_t *out ) const = 0;

   // Decompression
   // =============
   // On success, returns a positive value.
   // On errors, returns zero or a negative value.
   //
   // out_len MUST be the exact same as the in_len used when compress was called. In other word,
   // it has to be the original size.
   //
   // No more than 'out_len' bytes are ever written to 'out'. An error is returned
   // if 'out_len' is somehow too small.
   virtual int32_t decompress( const uint8_t *in, int32_t in_len, uint8_t *out, int32_t out_len ) const = 0;
};

class LZ4Compressor : public BlockCompressor {
public:

   virtual int32_t out_len_max( int32_t in_len ) const;

   virtual int32_t in_len_max( ) const;

   virtual int32_t compress( const uint8_t *in, int32_t in_len, uint8_t *out ) const;

   virtual int32_t decompress( const uint8_t *in, int32_t in_len, uint8_t *out, int32_t out_len ) const;
};


class ZLIBCompressor : public BlockCompressor {
public:

   virtual int32_t out_len_max( int32_t in_len ) const;

   virtual int32_t in_len_max( ) const;

   virtual int32_t compress( const uint8_t *in, int32_t in_len, uint8_t *out ) const;

   virtual int32_t decompress( const uint8_t *in, int32_t in_len, uint8_t *out, int32_t out_len ) const;
};

class FSECompressor : public BlockCompressor {
public:

   virtual int32_t out_len_max( int32_t in_len ) const;

   virtual int32_t in_len_max( ) const;

   virtual int32_t compress( const uint8_t *in, int32_t in_len, uint8_t *out ) const;

   virtual int32_t decompress( const uint8_t *in, int32_t in_len, uint8_t *out, int32_t out_len ) const;
};

// Allows to apply two BlockCompressor in series to the data.
class CompressorChain : public BlockCompressor {
  // compress() will do:
  //     in -> first compressor -> second compressor -> out
  // decompress() will do:
  //     in -> second decompressor -> first decompressor -> out
  //
public:
   CompressorChain( BlockCompressor &first, BlockCompressor &second ) : _first_compressor(first), _second_compressor(second) {}

   virtual int32_t out_len_max( int32_t in_len ) const;

   virtual int32_t in_len_max( ) const;

   virtual int32_t compress( const uint8_t *in, int32_t in_len, uint8_t *out ) const;

   virtual int32_t decompress( const uint8_t *in, int32_t in_len, uint8_t *out, int32_t out_len ) const;

private:
   BlockCompressor &_first_compressor;
   BlockCompressor &_second_compressor;
};

// Compressed serialization of a single 32-bits integer.
//
// The output of the compressor can be from 1 to 5 bytes.
//
// Space efficient only if the 32-bits value to be serialized is typically
// less or equal to (2^28)-1 == 268435455. This will output 4 bytes.
//
// Expected saving is:
//
//    uint32_t Range   |   #Output Byte
//    ================================
//      <=       127   |    1
//      <=     16383   |    2
//      <=   2097151   |    3
//      <= 268435455   |    4
//      <=4294967295   |    5
//



// Returns the number of bytes written into out (can be 1 to 5).
int32_t write_compact_32( uint32_t value, uint8_t* out );

// Returns the number of byte read (can be 1 to 5) and write
// the value into the int32_t pointer.
int32_t read_compact_32( const uint8_t* in, uint32_t *value );

// Utility function to get the serialization size without actually serializing.
int32_t serial_size_compact_32( uint32_t value );
