MD5
===

This package provides MD5sum capabilities to LuaJit, leveraging the FFI library.
Note that it does not work with Lua.

Installation
------------

```sh
$ torch-pkg install md5
```

Usage
-----

Require `md5`. Note that it does not create a global table.

```lua
> md5 = require 'md5'
> print(md5.string('hello world'))
5eb63bbbe01eeed093cb22bb8f5acdc3
```

Two functions are provided:
```lua
md5.string(<string>)
```
or
```lua
md5.file(<filename>)
```

`md5.string()` returns a string.
`md5.file()` returns a string if the given filename is valid, `nil` otherwise.

Advanced usage
--------------

For finer control over the library, one can also use the following functions:

```lua
md5.init(MD5_CTX *);
md5.update(MD5_CTX *, unsigned char *, unsigned int)
md5.final(unsigned char [16], MD5_CTX *);
```

Note that the functions expect FFI types. `MD5_CTX` is defined through FFI with:

```c
typedef struct {
  UINT4 state[4];                                   /* state (ABCD) */
  UINT4 count[2];        /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                         /* input buffer */
} MD5_CTX;
```

For more details, please refer to [the RFC1321 documentation](http://www.ietf.org/rfc/rfc1321.txt).
