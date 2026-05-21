FROM phpswoole/swoole:php8.1-alpine

COPY --from=mlocati/php-extension-installer /usr/bin/install-php-extensions /usr/local/bin/

RUN install-php-extensions pcntl bcmath inotify \
    && apk --no-cache add shadow supervisor nginx sqlite nginx-mod-http-brotli mysql-client git patch \
    && addgroup -S -g 1000 www && adduser -S -G www -u 1000 www

WORKDIR /www
COPY .docker /
COPY . /www

RUN tar -xzf /www/vendor_backup.tar.gz -C /www \
    && rm /www/vendor_backup.tar.gz \
    && php artisan storage:link \
    && cp /www/.env.example /www/.env \
    && chown -R www:www /www \
    && chmod -R 775 /www

CMD ["/usr/bin/supervisord", "--nodaemon", "-c", "/etc/supervisor/supervisord.conf"]
