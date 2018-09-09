local _M = {}
_M._VERSION = 1.0

function _M:md5(str)
    local resty_md5 = require "resty.md5"
    local md5 = resty_md5:new()
    md5:update(str)
    local digest = md5:final()
    local string = require "resty.string"
    return string.to_hex(digest)
end

function _M.authcode(self, str, op, key, expiry)
    -- 定义默认值
    op = op == nil and "DECODE" or op
    key = key == nil and "" or key
    expiry = expiry == nil and 0 or expiry
    if key == "" or str == "" then
        return ""
    end
    local ckey_length = 4
    -- 生成主秘钥
    local key = self:md5(key)
    -- 参与加密秘钥
    local keya = self:md5(string.sub(key, 0, 16))
    -- 校验数据有效
    local keyb = self:md5(string.sub(key, 17, 16 + 16))
    -- 动态秘钥
    local keyc = ""
    if op == "DECODE" then
        -- 解密 取串前4位作为动态秘钥
        keyc = string.sub(str, 0, ckey_length)
    else
        -- 加密 根据时间获得4位动态秘钥
        keyc = string.sub(self:md5(tostring(ngx.now() * 1000)), -ckey_length)
    end
    -- 加入动态秘钥
    local cryptkey = keya .. self:md5(keya .. keyc)
    local key_length = string.len(cryptkey)
    if op == "DECODE" then
        -- base64decode 获得需要解密的串
        str = ngx.decode_base64((string.sub(str, ckey_length + 1)))
    else
        -- 加入时间概念 以及验证字符串
        t = 0
        if expiry > 0 then
            t = ngx.time() + expiry
        end
        str = string.format("%010d",tonumber(t)) .. string.sub(self:md5(str .. keyb), 0, 16) .. str
    end
    local string_length = string.len(str)
    local box = {}
    i = 0
    -- 创建秘钥簿
    while (i < 256) do
        box[i] = i
        i = i + 1
    end
    local i = 0
    local rndkey = {}
    -- 对称算法
    while (i < 256) do
        local tmp = i % key_length
        rndkey[i] = string.byte(cryptkey, tmp + 1, tmp + 1)
        i = i + 1
    end

    local j = 0
    local i = 0
    while (i < 256) do
        j = (j + box[i] + rndkey[i]) % 256
        local tmp = box[i]
        box[i] = box[j]
        box[j] = tmp
        i = i + 1
    end
    local result = ""
    local a = 0
    local j = 0
    local i = 0
    local bit = require "bit"
    while (i < string_length) do
        a = (a + 1) % 256
        j = (j + box[a]) % 256
        tmp = box[a]
        box[a] = box[j]
        box[j] = tmp
        local tmp2 = bit.bxor(string.byte(str, i + 1, i + 1), box[(box[a] + box[j]) % 256])
        result = result .. string.char(tmp2)
        i = i + 1
    end
    if op == "DECODE" then
        -- 解密判断时间
        local expTime = tonumber(string.sub(result, 0, 10))
        if expTime ~= 0 and expTime - ngx.time() <= 0 then
            return ""
        end
        if string.sub(result, 11, 26) == string.sub(self:md5(string.sub(result, 27)..keyb), 0,16) then
            return string.sub(result, 27)
        end
    else
        -- 加密返回处理串
        return string.gsub(keyc .. ngx.encode_base64(result),"=","")
    end
    return ""
end

return _M
