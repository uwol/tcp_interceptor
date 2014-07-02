tcp_interceptor
===============

PHP script and C command-line application that act as reverse TCP/IP proxies for intercepting TCP connections.

Usage examples: 

* sudo php tcp_interceptor.php -t 173.194.70.94 -p 80
* sudo php tcp_interceptor.php -t 173.194.70.94 -p 80,443 -f 127.0.0.1 -i inbound.log -o outbound.log -v
