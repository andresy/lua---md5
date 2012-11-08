local md5 = {}

local ffi = require 'ffi'
local bit = require 'bit'

local PADDING = ffi.new('unsigned char[64]')
ffi.fill(PADDING, 64, 0)
PADDING[0] = 0x80

ffi.cdef[[
 
 /* Data structure for MD5 (Message-Digest) computation */
 typedef struct {
    unsigned int i[2];        /* number of _bits_ handled mod 2^64 */
    unsigned int buf[4];      /* scratch buffer */
    unsigned char input[64];     /* input buffer */
    unsigned char digest[16]; /* actual digest after MD5Final call */
 } MD5_CTX;

]]

local function md5init(mdContext)
   mdContext.i[0] = 0
   mdContext.i[1] = 0
   mdContext.buf[0] = 0x67452301
   mdContext.buf[1] = 0xefcdab89
   mdContext.buf[2] = 0x98badcfe
   mdContext.buf[3] = 0x10325476
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


local function md5transform(buf, input)
   local a = buf[0]
   local b = buf[1]
   local c = buf[2]
   local d = buf[3]

  -- Round 1
   local S11 = 7
   local S12 = 12
   local S13 = 17
   local S14 = 22
   a = FF ( a, b, c, d, input[ 0], S11, 3614090360) -- 1
   d = FF ( d, a, b, c, input[ 1], S12, 3905402710) -- 2
   c = FF ( c, d, a, b, input[ 2], S13,  606105819) -- 3
   b = FF ( b, c, d, a, input[ 3], S14, 3250441966) -- 4
   a = FF ( a, b, c, d, input[ 4], S11, 4118548399) -- 5
   d = FF ( d, a, b, c, input[ 5], S12, 1200080426) -- 6
   c = FF ( c, d, a, b, input[ 6], S13, 2821735955) -- 7
   b = FF ( b, c, d, a, input[ 7], S14, 4249261313) -- 8
   a = FF ( a, b, c, d, input[ 8], S11, 1770035416) -- 9
   d = FF ( d, a, b, c, input[ 9], S12, 2336552879) -- 10
   c = FF ( c, d, a, b, input[10], S13, 4294925233) -- 11
   b = FF ( b, c, d, a, input[11], S14, 2304563134) -- 12
   a = FF ( a, b, c, d, input[12], S11, 1804603682) -- 13
   d = FF ( d, a, b, c, input[13], S12, 4254626195) -- 14
   c = FF ( c, d, a, b, input[14], S13, 2792965006) -- 15
   b = FF ( b, c, d, a, input[15], S14, 1236535329) -- 16

 
   -- Round 2
   local S21 = 5
   local S22 = 9
   local S23 = 14
   local S24 = 20
   a = GG ( a, b, c, d, input[ 1], S21, 4129170786) -- 17
   d = GG ( d, a, b, c, input[ 6], S22, 3225465664) -- 18
   c = GG ( c, d, a, b, input[11], S23,  643717713) -- 19
   b = GG ( b, c, d, a, input[ 0], S24, 3921069994) -- 20
   a = GG ( a, b, c, d, input[ 5], S21, 3593408605) -- 21
   d = GG ( d, a, b, c, input[10], S22,   38016083) -- 22
   c = GG ( c, d, a, b, input[15], S23, 3634488961) -- 23
   b = GG ( b, c, d, a, input[ 4], S24, 3889429448) -- 24
   a = GG ( a, b, c, d, input[ 9], S21,  568446438) -- 25
   d = GG ( d, a, b, c, input[14], S22, 3275163606) -- 26
   c = GG ( c, d, a, b, input[ 3], S23, 4107603335) -- 27
   b = GG ( b, c, d, a, input[ 8], S24, 1163531501) -- 28
   a = GG ( a, b, c, d, input[13], S21, 2850285829) -- 29
   d = GG ( d, a, b, c, input[ 2], S22, 4243563512) -- 30
   c = GG ( c, d, a, b, input[ 7], S23, 1735328473) -- 31
   b = GG ( b, c, d, a, input[12], S24, 2368359562) -- 32
 
  -- Round 3
   local S31 = 4
   local S32 = 11
   local S33 = 16
   local S34 = 23
   a = HH ( a, b, c, d, input[ 5], S31, 4294588738) -- 33
   d = HH ( d, a, b, c, input[ 8], S32, 2272392833) -- 34
   c = HH ( c, d, a, b, input[11], S33, 1839030562) -- 35
   b = HH ( b, c, d, a, input[14], S34, 4259657740) -- 36
   a = HH ( a, b, c, d, input[ 1], S31, 2763975236) -- 37
   d = HH ( d, a, b, c, input[ 4], S32, 1272893353) -- 38
   c = HH ( c, d, a, b, input[ 7], S33, 4139469664) -- 39
   b = HH ( b, c, d, a, input[10], S34, 3200236656) -- 40
   a = HH ( a, b, c, d, input[13], S31,  681279174) -- 41
   d = HH ( d, a, b, c, input[ 0], S32, 3936430074) -- 42
   c = HH ( c, d, a, b, input[ 3], S33, 3572445317) -- 43
   b = HH ( b, c, d, a, input[ 6], S34,   76029189) -- 44
   a = HH ( a, b, c, d, input[ 9], S31, 3654602809) -- 45
   d = HH ( d, a, b, c, input[12], S32, 3873151461) -- 46
   c = HH ( c, d, a, b, input[15], S33,  530742520) -- 47
   b = HH ( b, c, d, a, input[ 2], S34, 3299628645) -- 48
   
  -- Round 4
   local S41 = 6
   local S42 = 10
   local S43 = 15
   local S44 = 21
   a = II ( a, b, c, d, input[ 0], S41, 4096336452) -- 49
   d = II ( d, a, b, c, input[ 7], S42, 1126891415) -- 50
   c = II ( c, d, a, b, input[14], S43, 2878612391) -- 51
   b = II ( b, c, d, a, input[ 5], S44, 4237533241) -- 52
   a = II ( a, b, c, d, input[12], S41, 1700485571) -- 53
   d = II ( d, a, b, c, input[ 3], S42, 2399980690) -- 54
   c = II ( c, d, a, b, input[10], S43, 4293915773) -- 55
   b = II ( b, c, d, a, input[ 1], S44, 2240044497) -- 56
   a = II ( a, b, c, d, input[ 8], S41, 1873313359) -- 57
   d = II ( d, a, b, c, input[15], S42, 4264355552) -- 58
   c = II ( c, d, a, b, input[ 6], S43, 2734768916) -- 59
   b = II ( b, c, d, a, input[13], S44, 1309151649) -- 60
   a = II ( a, b, c, d, input[ 4], S41, 4149444226) -- 61
   d = II ( d, a, b, c, input[11], S42, 3174756917) -- 62
   c = II ( c, d, a, b, input[ 2], S43,  718787259) -- 63
   b = II ( b, c, d, a, input[ 9], S44, 3951481745) -- 64
 
   buf[0] = buf[0] + a
   buf[1] = buf[1] + b
   buf[2] = buf[2] + c
   buf[3] = buf[3] + d

end

local function md5update(mdContext, inBuf, inLen)
   local input = ffi.new('unsigned int[16]')
   local mdi
   local i, ii
 
   -- compute number of bytes mod 64
   mdi = bit.band(bit.rshift(mdContext.i[0], 3), 0x3F)
 
   -- update number of bits
   if (mdContext.i[0] + bit.lshift(inLen, 3)) < mdContext.i[0] then
      mdContext.i[1] = mdContext.i[1] + 1
   end
   mdContext.i[0] = mdContext.i[0] + bit.lshift(inLen, 3)
   mdContext.i[1] = mdContext.i[1] + bit.rshift(inLen, 29)

--#ifdef  LITTLE_ENDIAN
  -- Speedup for little-endian machines suggested in MD5 report --P Karn
--    if mdi == 0 and bit.band(tonumber(ffi.cast('int', inBuf)), 3) == 0 then
--       while inLen >= 64 do
--          md5transform(mdContext.buf, inBuf)
--          inLen = inLen - 64
--          inBuf = inBuf + 64
--       end
--    end
--#endif  /* LITTLE_ENDIAN */
 
   while inLen > 0 do
      -- add new character to buffer, increment mdi
      mdContext.input[mdi] = inBuf[0]
      mdi = mdi + 1
      inBuf = inBuf + 1

      -- transform if necessary
      if mdi == 0x40 then
         local ii = 0
         for i=0,16-1 do
            input[i] = bit.bor(bit.lshift(mdContext.input[ii+3], 24),
                               bit.lshift(mdContext.input[ii+2], 16),
                               bit.lshift(mdContext.input[ii+1], 8),
                               mdContext.input[ii])
            ii = ii + 4
         end
         md5transform(mdContext.buf, input)
         mdi = 0
      end
      inLen = inLen - 1
   end
end

local function md5final(mdContext)
   local input = ffi.new('unsigned int[16]')
   local mdi
   local  i, ii
   local  padLen
 
   -- save number of bits
   input[14] = mdContext.i[0]
   input[15] = mdContext.i[1]
 
   -- compute number of bytes mod 64
   mdi = bit.band(bit.rshift(mdContext.i[0], 3), 0x3F)
 
   -- pad out to 56 mod 64
   padLen = mdi < 56 and 56 - mdi or 120 - mdi
   md5update(mdContext, PADDING, padLen)
 
   -- append length in bits and transform
   local ii = 0
   for i=0,14-1 do
      input[i] = bit.bor(bit.lshift(mdContext.input[ii+3], 24),
                         bit.lshift(mdContext.input[ii+2], 16),
                         bit.lshift(mdContext.input[ii+1], 8),
                         mdContext.input[ii])
      ii = ii + 4
   end
   md5transform(mdContext.buf, input)

   -- store buffer in digest
   local ii = 0
   for i=0,4-1 do
      mdContext.digest[ii]   = bit.band(mdContext.buf[i],                 0xFF)
      mdContext.digest[ii+1] = bit.band(bit.rshift(mdContext.buf[i],  8), 0xFF)
      mdContext.digest[ii+2] = bit.band(bit.rshift(mdContext.buf[i], 16), 0xFF)
      mdContext.digest[ii+3] = bit.band(bit.rshift(mdContext.buf[i], 24), 0xFF)
      ii = ii + 4
   end
end

function md5.string(str)
   local ctx = ffi.new('MD5_CTX')
   md5init(ctx)
   md5update(ctx, ffi.cast('const unsigned char*', str), #str)
   md5final(ctx)
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
