FROM nginx:alpine

COPY services/web/nginx.conf /etc/nginx/conf.d/default.conf
COPY services/web/html/ /usr/share/nginx/html/

EXPOSE 80
