# DZ09Bash
Написать скрипт для CRON, который раз в час формирует отчёт и отправляет его на заданную почту.  


Отчёт должен содержать:  

IP-адреса с наибольшим числом запросов (с момента последнего запуска);  
Запрашиваемые URL с наибольшим числом запросов (с момента последнего запуска);  
Ошибки веб-сервера/приложения (с момента последнего запуска);  
HTTP-коды ответов с указанием их количества (с момента последнего запуска).  

Скрипт должен предотвращать одновременный запуск нескольких копий, до его завершения.  

В письме должен быть прописан обрабатываемый временной диапазон.  
```
gor@testsrv:~$ sudo apt install postfix
# TLS parameters
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key
smtpd_tls_security_level=may

smtp_tls_CApath=/etc/ssl/certs
#smtp_tls_security_level=may
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
smtp_tls_wrappermode = yes
smtp_tls_security_level = encrypt

smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = testsrv
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mydestination = $myhostname, testsrv, localhost.localdomain, , localhost
#relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = all

relayhost = [smtp.yandex.ru]:465
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/ssl/certs/ca-certificates.crt
smtp_use_tls = yes
smtp_generic_maps = hash:/etc/postfix/generic

gor@testsrv:~$ sudo echo "test" | mail -s "test" m.guseva@kalinaoil.pro
2025-12-08T11:03:55.730680+00:00 testsrv postfix/smtp[61027]: D3E1A44CF1: to=<m.guseva@kalinaoil.pro>, relay=smtp.yandex.ru[77.88.21.158]:465, delay=0.87, delays=0.02/0.07/0.19/0.59, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued on mail-nwsmtp-smtp-production-main-71.sas.yp-c.yandex.net 1765191835-s3KHhagLLiE0-PU70LIP1)
