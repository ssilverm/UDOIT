#!/usr/bin/env bash
service nginx start
php bin/console doctrine:migrations:migrate
chown -R www-data:www-data var
chown -R www-data:www-data cache
php-fpm
