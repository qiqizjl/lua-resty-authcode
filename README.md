Name
====

lua-resty-authcode - DiscuzX AuthCode For Lua


Status
======

This library is production ready.


Synopsis
========
Some simple examples:
```lua
    http {
        ...
        lua_package_path "/path/to/lua-resty-authcode/lib/?.lua;;";
        ...
    }
    server{
        ...
        content_by_lua_block {
            local authcode = require "resty.authcode"
            local result = authcode:authcode("2617ibqLZGzCIvf/q0HPtQQvPizyRgYTF1bwbQ6KLlncHc8TOUi9D6s","DECODE","123123123")
            ngx.say(result)
        }
        ...
    }
```
[Back to TOC](#table-of-contents)

Methods
=======

[Back to TOC](#table-of-contents)

autcode
-------
`syntax: result = authcode:authcode(str,operation,key,expiry)`

* `str`

    String that needs to be manipulated
* `operation`

    Action.`ENCODE` or `DECODE`
* `key`

    Key required for encryption
* `expiry`

    Encrypted string expiration time, beyond aging will not be decrypted. Default 0, permanent valid
