FROM alpine:3.24
RUN apk upgrade --no-cache && apk add --no-cache 'nginx>=1.30.7-r0'
COPY infra/nginx.conf /etc/nginx/nginx.conf
COPY apps/web /usr/share/nginx/html
USER nginx
CMD ["nginx", "-g", "daemon off;"]
