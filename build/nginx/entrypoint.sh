#!/usr/bin/env bash
service nginx start
php bin/console doctrine:migrations:migrate
php-fpm
chown -R www-data:www-data var
chown -R www-data:www-data cache
