FROM openresty/openresty:alpine

# Install lua-resty-http directly into openresty's lua path (no luarocks needed)
RUN apk add --no-cache git \
    && git clone --depth=1 https://github.com/ledgetech/lua-resty-http.git /tmp/lua-resty-http \
    && cp -r /tmp/lua-resty-http/lib/resty/. /usr/local/openresty/lualib/resty/ \
    && rm -rf /tmp/lua-resty-http

# Copy NGINX configuration
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# Copy Lua modules
COPY lua/ /usr/local/openresty/nginx/lua/

# Copy Web UI static files
COPY html/ /usr/local/openresty/nginx/html/

# Create log directory
RUN mkdir -p /var/log/nginx

EXPOSE 80

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
