FROM nginx:alpine

COPY src /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Update Alpine packages, then remove package-index/cache files in the same layer.
RUN apk update && apk upgrade && rm -rf /var/cache/apk/*

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
