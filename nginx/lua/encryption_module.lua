-- Field-level encryption module for NGINX

local cjson = require "cjson"
local http = require "resty.http"

local _M = {}

-- Module configuration
_M.config = nil
_M.kms_bridge_url = "http://kms-bridge:5001"

-- Minimal YAML parser for simple key: value and list structures
-- Supports the config.yaml format without requiring lyaml/C extensions
local function parse_simple_yaml(content)
    local result = {}
    local stack = {{obj = result, indent = -1}}

    for line in (content .. "\n"):gmatch("([^\n]*)\n") do
        -- Strip comments and trailing whitespace
        line = line:gsub("#.*$", ""):gsub("%s+$", "")
        if line:match("%S") then
            local indent = #line:match("^(%s*)") 
            local trimmed = line:match("^%s*(.-)%s*$")

            -- Pop stack to current indent level
            while #stack > 1 and stack[#stack].indent >= indent do
                table.remove(stack)
            end

            local parent = stack[#stack].obj

            if trimmed:sub(1,1) == "-" then
                -- List item
                local val = trimmed:match("^%-%s*(.+)$")
                if val then
                    -- List item with key: value pairs (e.g. "- path: $.ssn")
                    local k, v = val:match("^([%w_]+):%s*(.*)$")
                    if k then
                        local item = {[k] = v}
                        table.insert(parent, item)
                        table.insert(stack, {obj = item, indent = indent})
                    else
                        table.insert(parent, val)
                    end
                end
            else
                local k, v = trimmed:match("^([%w_]+):%s*(.*)$")
                if k then
                    if v == "" then
                        -- Nested object or list coming
                        local next_line = content:match("\n" .. string.rep(" ", indent + 2) .. "%-")
                        if next_line then
                            parent[k] = {}
                        else
                            parent[k] = {}
                        end
                        table.insert(stack, {obj = parent[k], indent = indent})
                    else
                        parent[k] = v
                    end
                end
            end
        end
    end
    return result
end

-- Load configuration from YAML file
function _M.load_config(config_path)
    local file = io.open(config_path, "r")
    
    if not file then
        ngx.log(ngx.ERR, "Failed to open config file: ", config_path)
        return nil, "Config file not found"
    end
    
    local content = file:read("*all")
    file:close()
    
    local ok, config = pcall(parse_simple_yaml, content)
    if not ok then
        ngx.log(ngx.ERR, "Failed to parse YAML config: ", config)
        return nil, "Invalid YAML syntax"
    end
    
    -- Validate required fields
    if not config.kms or not config.kms.region or not config.kms.key_id then
        return nil, "ERROR: Invalid configuration in config.yaml\nMissing required KMS configuration (kms.region and kms.key_id)"
    end
    
    if not config.encryption or not config.encryption.fields then
        return nil, "ERROR: Invalid configuration in config.yaml\nMissing required encryption field configuration (encryption.fields)"
    end
    
    if type(config.encryption.fields) ~= "table" or #config.encryption.fields == 0 then
        return nil, "ERROR: Invalid configuration in config.yaml\n'encryption.fields' must be a non-empty list"
    end
    
    -- Validate each field selector's JSONPath syntax
    -- Valid: starts with $. followed by dot-separated identifiers (no double dots, wildcards, or arrays)
    for i, field in ipairs(config.encryption.fields) do
        if type(field) ~= "table" or not field.path then
            return nil, string.format(
                "ERROR: Invalid configuration in config.yaml\nField entry %d is missing required 'path' key", i)
        end
        local path = field.path
        -- Must start with $. and contain only word chars separated by single dots
        if not path:match("^%$%.[a-zA-Z_][a-zA-Z0-9_]*") then
            return nil, string.format(
                "ERROR: Invalid configuration in config.yaml\n"
                .. "Field selector '%s' has invalid syntax "
                .. "(use dot notation like $.field or $.parent.child; "
                .. "double dots, wildcards, and array notation are not supported)", path)
        end
        -- Reject double dots
        if path:find("%.%.") then
            return nil, string.format(
                "ERROR: Invalid configuration in config.yaml\n"
                .. "Field selector '%s' has invalid syntax (double dots not supported)", path)
        end
        -- Reject wildcards
        if path:find("%*") then
            return nil, string.format(
                "ERROR: Invalid configuration in config.yaml\n"
                .. "Field selector '%s' has invalid syntax (wildcards not supported)", path)
        end
        -- Reject array notation
        if path:find("%[") then
            return nil, string.format(
                "ERROR: Invalid configuration in config.yaml\n"
                .. "Field selector '%s' has invalid syntax (array notation not supported)", path)
        end
    end
    
    _M.config = config
    ngx.log(ngx.INFO, "Loaded config: region=", config.kms.region, 
            ", key_id=", config.kms.key_id,
            ", fields=", #config.encryption.fields)
    
    return config
end

-- Extract field value from JSON object using JSONPath
-- Supports simple dot notation: $.field or $.parent.child
function _M.get_field_value(obj, path)
    -- Remove leading $. if present
    local clean_path = path:gsub("^%$%.", "")
    
    -- Split path by dots
    local parts = {}
    for part in clean_path:gmatch("[^.]+") do
        table.insert(parts, part)
    end
    
    -- Navigate through object
    local current = obj
    for _, part in ipairs(parts) do
        if type(current) ~= "table" then
            return nil
        end
        current = current[part]
        if current == nil then
            return nil
        end
    end
    
    return current
end

-- Set field value in JSON object using JSONPath
function _M.set_field_value(obj, path, value)
    local clean_path = path:gsub("^%$%.", "")
    local parts = {}
    for part in clean_path:gmatch("[^.]+") do
        table.insert(parts, part)
    end
    
    -- Navigate to parent
    local current = obj
    for i = 1, #parts - 1 do
        if type(current) ~= "table" then
            return false
        end
        if current[parts[i]] == nil then
            current[parts[i]] = {}
        end
        current = current[parts[i]]
    end
    
    -- Set final value
    if type(current) == "table" then
        current[parts[#parts]] = value
        return true
    end
    
    return false
end

-- Call KMS bridge HTTP API
function _M.call_kms_bridge(endpoint, payload)
    local httpc = http.new()
    httpc:set_timeout(5000)  -- 5 second timeout
    
    local url = _M.kms_bridge_url .. endpoint
    local body = cjson.encode(payload)
    
    local res, err = httpc:request_uri(url, {
        method = "POST",
        body = body,
        headers = {
            ["Content-Type"] = "application/json",
        }
    })
    
    if not res then
        ngx.log(ngx.ERR, "KMS bridge request failed: ", err)
        return nil, "KMS bridge unavailable: " .. (err or "unknown error")
    end
    
    if res.status ~= 200 then
        local error_msg = "KMS bridge error"
        if res.body then
            local ok, error_data = pcall(cjson.decode, res.body)
            if ok and error_data.error then
                error_msg = error_data.error
            end
        end
        ngx.log(ngx.ERR, "KMS bridge returned status ", res.status, ": ", error_msg)
        return nil, error_msg
    end
    
    local ok, result = pcall(cjson.decode, res.body)
    if not ok then
        ngx.log(ngx.ERR, "Failed to parse KMS bridge response: ", result)
        return nil, "Invalid response from KMS bridge"
    end
    
    return result
end

-- Encrypt a single field value
function _M.encrypt_value(plaintext, key_id)
    local payload = {
        plaintext = tostring(plaintext),
        key_id = key_id
    }
    
    local result, err = _M.call_kms_bridge("/encrypt", payload)
    if not result then
        return nil, err
    end
    
    return result
end

-- Decrypt a single field value
function _M.decrypt_value(ciphertext)
    local payload = {
        ciphertext = ciphertext
    }
    
    local result, err = _M.call_kms_bridge("/decrypt", payload)
    if not result then
        return nil, err
    end
    
    return result
end

-- Encrypt sensitive fields in request body
-- Stores metrics in ngx.ctx for later use in body_filter_by_lua_block
function _M.encrypt_request_fields(body)
    if not _M.config then
        ngx.log(ngx.ERR, "Configuration not loaded")
        return nil, "Configuration not loaded"
    end
    
    -- Parse JSON body
    local ok, data = pcall(cjson.decode, body)
    if not ok then
        ngx.log(ngx.WARN, "Failed to parse JSON body: ", data)
        return nil, "Invalid JSON"
    end
    
    local fields_encrypted = {}
    local total_encrypt_time = 0
    local last_result = nil
    
    -- Process each configured field
    for _, field_config in ipairs(_M.config.encryption.fields) do
        local field_path = field_config.path
        local field_value = _M.get_field_value(data, field_path)
        
        if field_value ~= nil and field_value ~= "" then
            -- Encrypt the field
            local result, err = _M.encrypt_value(field_value, _M.config.kms.key_id)
            
            if not result then
                ngx.log(ngx.ERR, "Failed to encrypt field ", field_path, ": ", err)
                return nil, "Encryption failed: " .. err
            end
            
            -- Replace with encrypted value
            _M.set_field_value(data, field_path, result.ciphertext)
            
            -- Log encryption
            ngx.log(ngx.INFO, "[ENCRYPTED] field=", field_path, 
                    ", kms_key=", result.key_id,
                    ", duration=", result.duration_ms, "ms",
                    ", value=", string.sub(result.ciphertext, 1, 50), "...")
            
            table.insert(fields_encrypted, field_path)
            total_encrypt_time = total_encrypt_time + result.duration_ms
            last_result = result
        end
    end
    
    if #fields_encrypted == 0 then
        ngx.log(ngx.INFO, "No sensitive fields found in request, passing through")
    else
        ngx.log(ngx.INFO, "Encrypted ", #fields_encrypted, " fields in ", 
                total_encrypt_time, "ms")
    end
    
    -- Store metrics in ngx.ctx for body_filter_by_lua_block
    ngx.ctx.encrypt_metrics = {
        encrypt_time_ms = total_encrypt_time,
        fields_encrypted = fields_encrypted,
        kms_endpoint = last_result and last_result.endpoint or
                       ("https://kms." .. _M.config.kms.region .. ".amazonaws.com/"),
        kms_region = _M.config.kms.region,
        kms_key_id = last_result and last_result.key_id or _M.config.kms.key_id,
    }
    
    -- Store encrypted payload snapshot for Web UI
    ngx.ctx.encrypted_payload = data
    
    -- Return modified JSON
    local modified_body = cjson.encode(data)
    return modified_body, nil
end

-- Decrypt sensitive fields in response body
-- Stores decrypt timing in ngx.ctx and returns decrypted data
function _M.decrypt_response_fields(body)
    if not _M.config then
        ngx.log(ngx.ERR, "Configuration not loaded")
        return nil, "Configuration not loaded"
    end
    
    -- Parse JSON body
    local ok, data = pcall(cjson.decode, body)
    if not ok then
        ngx.log(ngx.WARN, "Failed to parse JSON response: ", data)
        return body, nil  -- Return original if not JSON
    end
    
    local fields_decrypted = {}
    local total_decrypt_time = 0
    
    -- Process each configured field
    for _, field_config in ipairs(_M.config.encryption.fields) do
        local field_path = field_config.path
        local field_value = _M.get_field_value(data, field_path)
        
        -- Check if field looks like encrypted data (starts with AQICA)
        if field_value and type(field_value) == "string" and 
           string.sub(field_value, 1, 5) == "AQICA" then
            
            -- Decrypt the field
            local result, err = _M.decrypt_value(field_value)
            
            if not result then
                ngx.log(ngx.ERR, "Failed to decrypt field ", field_path, ": ", err)
                return nil, "Decryption failed: " .. err
            end
            
            -- Replace with decrypted value
            _M.set_field_value(data, field_path, result.plaintext)
            
            -- Log decryption
            ngx.log(ngx.INFO, "[DECRYPTED] field=", field_path,
                    ", kms_key=", result.key_id,
                    ", duration=", result.duration_ms, "ms",
                    ", value=", result.plaintext)
            
            table.insert(fields_decrypted, field_path)
            total_decrypt_time = total_decrypt_time + result.duration_ms
        end
    end
    
    if #fields_decrypted > 0 then
        ngx.log(ngx.INFO, "Decrypted ", #fields_decrypted, " fields in ",
                total_decrypt_time, "ms")
    end
    
    -- Store decrypt timing in ngx.ctx for metrics injection
    if ngx.ctx.encrypt_metrics then
        ngx.ctx.encrypt_metrics.decrypt_time_ms = total_decrypt_time
    end
    
    -- Return modified JSON
    local modified_body = cjson.encode(data)
    return modified_body, nil
end

return _M
