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
md5.file(<filename>')
```

`md5.string()` returns a string.
`md5.file()` returns a string if the given filename is valid, `nil` otherwise.
