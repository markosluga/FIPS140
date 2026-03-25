FROM nginx:alpine

# Install njs (NGINX JavaScript) module
RUN apk add --no-cache nginx-module-njs

# Copy NGINX configuration (njs version)
COPY nginx.njs.conf /etc/nginx/nginx.conf

# Copy JavaScript modules
COPY js/ /etc/nginx/js/

# Copy Web UI static files
COPY html/ /usr/share/nginx/html/

# Create log directory
RUN mkdir -p /var/log/nginx

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
