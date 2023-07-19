#!/usr/bin/env bash
service nginx start
php bin/console doctrine:migrations:migrate
php-fpm
