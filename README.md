tcp_interceptor
===============

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0)

PHP script and C command-line application that act as reverse TCP/IP proxies for intercepting TCP connections.

Usage examples:

* sudo php tcp_interceptor.php -t 173.194.70.94 -p 80
* sudo php tcp_interceptor.php -t 173.194.70.94 -p 80,443 -f 127.0.0.1 -i inbound.log -o outbound.log -v
