local md5 = {}

local ffi = require 'ffi'
local bit = require 'bit'

local S11 = 7
local S12 = 12
local S13 = 17
local S14 = 22
local S21 = 5
local S22 = 9
local S23 = 14
local S24 = 20
local S31 = 4
local S32 = 11
local S33 = 16
local S34 = 23
local S41 = 6
local S42 = 10
local S43 = 15
local S44 = 21

local PADDING = ffi.new('unsigned char[64]')
ffi.fill(PADDING, 64, 0)
PADDING[0] = 0x80

ffi.cdef[[
 
 /* Data structure for MD5 (Message-Digest) computation */
 typedef struct {
    unsigned int state[4];        /* state (ABCD) */
    unsigned int count[2];      /* number of bits, modulo 2^64 (lsb first) */
    unsigned char buffer[64];     /* input buffer */
    unsigned char digest[16]; /* actual digest after Md5.Final call */
 } MD5_CTX;

]]

function md5.init(context)
   context.count[0] = 0
   context.count[1] = 0

   -- load magic initialization constants.
   context.state[0] = 0x67452301
   context.state[1] = 0xefcdab89
   context.state[2] = 0x98badcfe
   context.state[3] = 0x10325476
end

local function F(x, y, z)
   return bit.bxor(z, bit.band(x, bit.bxor(y, z)))
--   return bit.bor(bit.band(x, y), bit.band(bit.bnot(x), z))
end

local function G(x, y, z)
   return bit.bor(bit.band(x, z), bit.band(y, bit.bnot(z)))
end

local function H(x, y, z)
   return bit.bxor(x, y, z)
end

local function I(x, y, z)
   return bit.bxor(y, bit.bor(x, bit.bnot(z)))
end

local function ROTATE_LEFT(x, n)
   return bit.bor(bit.lshift(x, n), bit.rshift(x, 32-n))
end

local function FF(a, b, c, d, x, s, ac)
   a = a + F(b, c, d) + x + ac
   a = ROTATE_LEFT(a, s)
   a = a + b
   return a
end

local function GG(a, b, c, d, x, s, ac)
   a = a + G(b, c, d) + x + ac
   a = ROTATE_LEFT(a, s)
   a = a + b
   return a
end

local function HH(a, b, c, d, x, s, ac)
   a = a + H(b, c, d) + x + ac
   a = ROTATE_LEFT(a, s)
   a = a + b
   return a
end

local function II(a, b, c, d, x, s, ac)
   a = a + I(b, c, d) + x + ac
   a = ROTATE_LEFT(a, s)
   a = a + b
   return a
end

-- Encodes input (UINT4) into output (unsigned char).
-- Assumes len is a multiple of 4.
local function encode(output, input, len)
   local i = 0
   local j = 0
   while j < len do
      output[j]   = bit.band(input[i],                 0xff)
      output[j+1] = bit.band(bit.rshift(input[i],  8), 0xff)
      output[j+2] = bit.band(bit.rshift(input[i], 16), 0xff)
      output[j+3] = bit.band(bit.rshift(input[i], 24), 0xff)
      i = i + 1
      j = j + 4
   end
end

-- Decodes input (unsigned char) into output (UINT4).
-- Assumes len is a multiple of 4.
local function decode(output, input, len)
   local i = 0
   local j = 0
   while j < len do
      output[i] = bit.bor(bit.lshift(input[j+3], 24),
                          bit.lshift(input[j+2], 16),
                          bit.lshift(input[j+1], 8),
                          input[j])
      i = i + 1
      j = j + 4
   end
end

   local x = ffi.new('unsigned int[16]')

local function md5transform(state, block)
   local a, b, c, d = state[0], state[1], state[2], state[3]

   decode(x, block, 64)

   -- Round 1
   a = FF(a, b, c, d, x[ 0], S11, 0xd76aa478) -- 1
   d = FF(d, a, b, c, x[ 1], S12, 0xe8c7b756) -- 2
   c = FF(c, d, a, b, x[ 2], S13, 0x242070db) -- 3
   b = FF(b, c, d, a, x[ 3], S14, 0xc1bdceee) -- 4
   a = FF(a, b, c, d, x[ 4], S11, 0xf57c0faf) -- 5
   d = FF(d, a, b, c, x[ 5], S12, 0x4787c62a) -- 6
   c = FF(c, d, a, b, x[ 6], S13, 0xa8304613) -- 7
   b = FF(b, c, d, a, x[ 7], S14, 0xfd469501) -- 8
   a = FF(a, b, c, d, x[ 8], S11, 0x698098d8) -- 9
   d = FF(d, a, b, c, x[ 9], S12, 0x8b44f7af) -- 10
   c = FF(c, d, a, b, x[10], S13, 0xffff5bb1) -- 11
   b = FF(b, c, d, a, x[11], S14, 0x895cd7be) -- 12
   a = FF(a, b, c, d, x[12], S11, 0x6b901122) -- 13
   d = FF(d, a, b, c, x[13], S12, 0xfd987193) -- 14
   c = FF(c, d, a, b, x[14], S13, 0xa679438e) -- 15
   b = FF(b, c, d, a, x[15], S14, 0x49b40821) -- 16

   -- Round 2
   a = GG(a, b, c, d, x[ 1], S21, 0xf61e2562) -- 17
   d = GG(d, a, b, c, x[ 6], S22, 0xc040b340) -- 18
   c = GG(c, d, a, b, x[11], S23, 0x265e5a51) -- 19
   b = GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa) -- 20
   a = GG(a, b, c, d, x[ 5], S21, 0xd62f105d) -- 21
   d = GG(d, a, b, c, x[10], S22,  0x2441453) -- 22
   c = GG(c, d, a, b, x[15], S23, 0xd8a1e681) -- 23
   b = GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8) -- 24
   a = GG(a, b, c, d, x[ 9], S21, 0x21e1cde6) -- 25
   d = GG(d, a, b, c, x[14], S22, 0xc33707d6) -- 26
   c = GG(c, d, a, b, x[ 3], S23, 0xf4d50d87) -- 27
   b = GG(b, c, d, a, x[ 8], S24, 0x455a14ed) -- 28
   a = GG(a, b, c, d, x[13], S21, 0xa9e3e905) -- 29
   d = GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8) -- 30
   c = GG(c, d, a, b, x[ 7], S23, 0x676f02d9) -- 31
   b = GG(b, c, d, a, x[12], S24, 0x8d2a4c8a) -- 32

   -- Round 3
   a = HH(a, b, c, d, x[ 5], S31, 0xfffa3942) -- 33
   d = HH(d, a, b, c, x[ 8], S32, 0x8771f681) -- 34
   c = HH(c, d, a, b, x[11], S33, 0x6d9d6122) -- 35
   b = HH(b, c, d, a, x[14], S34, 0xfde5380c) -- 36
   a = HH(a, b, c, d, x[ 1], S31, 0xa4beea44) -- 37
   d = HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9) -- 38
   c = HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60) -- 39
   b = HH(b, c, d, a, x[10], S34, 0xbebfbc70) -- 40
   a = HH(a, b, c, d, x[13], S31, 0x289b7ec6) -- 41
   d = HH(d, a, b, c, x[ 0], S32, 0xeaa127fa) -- 42
   c = HH(c, d, a, b, x[ 3], S33, 0xd4ef3085) -- 43
   b = HH(b, c, d, a, x[ 6], S34,  0x4881d05) -- 44
   a = HH(a, b, c, d, x[ 9], S31, 0xd9d4d039) -- 45
   d = HH(d, a, b, c, x[12], S32, 0xe6db99e5) -- 46
   c = HH(c, d, a, b, x[15], S33, 0x1fa27cf8) -- 47
   b = HH(b, c, d, a, x[ 2], S34, 0xc4ac5665) -- 48

   -- Round 4
   a = II(a, b, c, d, x[ 0], S41, 0xf4292244) -- 49
   d = II(d, a, b, c, x[ 7], S42, 0x432aff97) -- 50
   c = II(c, d, a, b, x[14], S43, 0xab9423a7) -- 51
   b = II(b, c, d, a, x[ 5], S44, 0xfc93a039) -- 52
   a = II(a, b, c, d, x[12], S41, 0x655b59c3) -- 53
   d = II(d, a, b, c, x[ 3], S42, 0x8f0ccc92) -- 54
   c = II(c, d, a, b, x[10], S43, 0xffeff47d) -- 55
   b = II(b, c, d, a, x[ 1], S44, 0x85845dd1) -- 56
   a = II(a, b, c, d, x[ 8], S41, 0x6fa87e4f) -- 57
   d = II(d, a, b, c, x[15], S42, 0xfe2ce6e0) -- 58
   c = II(c, d, a, b, x[ 6], S43, 0xa3014314) -- 59
   b = II(b, c, d, a, x[13], S44, 0x4e0811a1) -- 60
   a = II(a, b, c, d, x[ 4], S41, 0xf7537e82) -- 61
   d = II(d, a, b, c, x[11], S42, 0xbd3af235) -- 62
   c = II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb) -- 63
   b = II(b, c, d, a, x[ 9], S44, 0xeb86d391) -- 64
 
   state[0] = state[0] + a
   state[1] = state[1] + b
   state[2] = state[2] + c
   state[3] = state[3] + d

end

function md5.update(context, input, inputLen) 
   -- compute number of bytes mod 64
   local index = bit.band(bit.rshift(context.count[0], 3), 0x3f)
 
   -- update number of bits
   local prev = context.count[0]
   context.count[0] = context.count[0] + bit.lshift(inputLen, 3)
   if context.count[0] < prev then
      context.count[1] = context.count[1] + 1
   end
   context.count[1] = context.count[1] + bit.rshift(inputLen, 29)

   -- transform as many times as possible
   local partLen = 64 - index
   local i = partLen
   if inputLen >= partLen then
      ffi.copy(context.buffer+index, input, partLen)
      md5transform(context.state, context.buffer)

      while i + 63 < inputLen do
         md5transform(context.state, input+i)
         i = i + 64
      end

      index = 0
   else
      i = 0
   end
   -- buffer remaining input
   ffi.copy(context.buffer+index, input+i, inputLen-i)
end

function md5.final(context)
   local bits = ffi.new('unsigned char[8]')

   encode(bits, context.count, 8)
 
   -- pad out to 56 mod 64
   local index = bit.band(bit.rshift(context.count[0], 3), 0x3f)
   local padLen = index < 56 and 56 - index or 120 - index
   md5.update(context, PADDING, padLen)
 
   -- append length (before padding)
   md5.update(context, bits, 8)

   -- storage state in digest
   encode(context.digest, context.state, 16)
end

function md5.string(str)
   local ctx = ffi.new('MD5_CTX')
   md5.init(ctx)
   md5.update(ctx, ffi.cast('const unsigned char*', str), #str)
   md5.final(ctx)
   local strsum = {}
   for i=0,16-1 do
      table.insert(strsum, bit.tohex(ctx.digest[i], 2))
   end
   return table.concat(strsum)
end

function md5.file(filename)
   local f = io.open(filename)
   if f then
      local txt = f:read('*all')
      f:close()
      return md5.string(txt)
   end
end

return md5
