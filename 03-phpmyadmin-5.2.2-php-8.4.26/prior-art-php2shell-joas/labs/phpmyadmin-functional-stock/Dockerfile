ARG PHP_IMAGE=php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a
FROM ${PHP_IMAGE}
ARG PMA_SHA256=8551c8bf3b166f232d5cf64bac877472e9d0cb8f2fe1858fab24f975e7d765b6

RUN docker-php-ext-install mysqli

RUN curl -fsSL https://files.phpmyadmin.net/phpMyAdmin/5.2.2/phpMyAdmin-5.2.2-all-languages.tar.gz \
    -o /tmp/phpmyadmin.tar.gz \
    && echo "${PMA_SHA256}  /tmp/phpmyadmin.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/phpmyadmin.tar.gz -C /var/www/html --strip-components=1 \
    && rm /tmp/phpmyadmin.tar.gz \
    && chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

COPY config.inc.php /var/www/html/config.inc.php
RUN chown www-data:www-data /var/www/html/config.inc.php
