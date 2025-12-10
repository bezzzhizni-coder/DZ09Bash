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


gor@testsrv:~$ cat /usr/local/bin/nginx-report.sh
#!/bin/bash -x

LOG_FILE="/var/log/nginx/access.log" 
TEMP_DIR="/tmp/nginx-report"
LOCK_FILE="$TEMP_DIR/lock"
REPORT_FILE="$TEMP_DIR/report.txt"
MAIL_TO="m.guseva@kalinaoil.pro"
MAIL_FROM="goryacheva@bazis.vrn.ru"
SUBJECT="Nginx Report: $(date +'%Y-%m-%d %H:%M')"


mkdir -p "$TEMP_DIR"

# Проверка на наличие lock‑файла (защита от параллельного запуска)
if [ -f "$LOCK_FILE" ]; then
    echo "Другой экземпляр скрипта уже работает. Выход."
    exit 1
fi

# Создаём lock‑файл
touch "$LOCK_FILE"


if [ -f "$TEMP_DIR/last_run" ]; then
    LAST_RUN=$(cat "$TEMP_DIR/last_run")
else

    LAST_RUN=$(head -1 "$LOG_FILE" | awk '{print $4}' | sed 's/\[//')
fi


date +'%d/%b/%Y:%H:%M:%S' > "$TEMP_DIR/last_run"


grep "$LAST_RUN" "$LOG_FILE" > "$TEMP_DIR/recent.log" || cp "$LOG_FILE" "$TEMP_DIR/recent.log"

# Собираем данные

echo "Отчёт по Nginx" > "$REPORT_FILE"
echo "Период: с $LAST_RUN до $(date +'%d/%b/%Y:%H:%M:%S')" >> "$REPORT_FILE"
echo "=========================================" >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "1. IP‑адреса с наибольшим числом запросов:" >> "$REPORT_FILE"
awk '{print $1}' "$TEMP_DIR/recent.log" | sort | uniq -c | sort -nr | head -10 >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "2. Запрашиваемые URL с наибольшим числом запросов:" >> "$REPORT_FILE"
awk '{print $7}' "$TEMP_DIR/recent.log" | sort | uniq -c | sort -nr | head -10 >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "3. Ошибки веб‑сервера (HTTP-коды 4xx, 5xx):" >> "$REPORT_FILE"
grep -E ' "(4|5)[0-9][0-9] "' "$TEMP_DIR/recent.log" | awk '{print $9, $7}' | sort | uniq -c | sort -nr >> "$REPORT_FILE"

echo "" >> "$REPORT_FILE"
echo "4. Все HTTP‑коды ответов и их количество:" >> "$REPORT_FILE"
awk '{print $9}' "$TEMP_DIR/recent.log" | grep -E '^[1-5][0-9][0-9]$' | sort | uniq -c | sort -nr >> "$REPORT_FILE"

# Отправляем письмо
if command -v mail > /dev/null; then
    mail -s "$SUBJECT" -r "$MAIL_FROM" "$MAIL_TO" < "$REPORT_FILE"
elif command -v sendmail > /dev/null; then
    (echo "Subject: $SUBJECT"; echo "From: $MAIL_FROM"; echo ""; cat "$REPORT_FILE") | sendmail "$MAIL_TO"
else
    echo "Не найден mail или sendmail. Установите пакет mailutils или sendmail."
fi

# Удаляем lock‑файл
rm -f "$LOCK_FILE"

# rm -f "$TEMP_DIR/recent.log"

gor@testsrv:~$ sudo chmod +x nginx-report.sh
gor@testsrv:~$ sudo  /usr/local/bin/nginx-report.sh

gor@testsrv:~$ sudo crontab -l
0 * * * * /usr/local/bin/nginx-report.sh >> /var/log/nginx-report-cron.log 2>&1

gor@testsrv:~$ cat /var/log/nginx-report-cron.log
+ LOG_FILE=/var/log/nginx/access.log
+ TEMP_DIR=/tmp/nginx-report
+ LOCK_FILE=/tmp/nginx-report/lock
+ REPORT_FILE=/tmp/nginx-report/report.txt
+ MAIL_TO=m.guseva@kalinaoil.pro
+ MAIL_FROM=goryacheva@bazis.vrn.ru
++ date '+%Y-%m-%d %H:%M'
+ SUBJECT='Nginx Report: 2025-12-08 14:00'
+ mkdir -p /tmp/nginx-report
+ '[' -f /tmp/nginx-report/lock ']'
+ touch /tmp/nginx-report/lock
+ '[' -f /tmp/nginx-report/last_run ']'
++ cat /tmp/nginx-report/last_run
+ LAST_RUN=08/дек/2025:13:19:47
+ date +%d/%b/%Y:%H:%M:%S
+ grep 08/дек/2025:13:19:47 /var/log/nginx/access.log
+ cp /var/log/nginx/access.log /tmp/nginx-report/recent.log
+ echo 'Отчёт по Nginx'
++ date +%d/%b/%Y:%H:%M:%S
+ echo 'Период: с 08/дек/2025:13:19:47 до 08/дек/2025:14:00:01'
+ echo =========================================
+ echo ''
+ echo '1. IP‑адреса с наибольшим числом запросов:'
+ awk '{print $1}' /tmp/nginx-report/recent.log
+ sort
+ uniq -c
+ sort -nr
+ head -10
+ echo ''
+ echo '2. Запрашиваемые URL с наибольшим числом запросов:'
+ awk '{print $7}' /tmp/nginx-report/recent.log
+ sort
+ uniq -c
+ sort -nr
+ head -10
+ echo ''
+ echo '3. Ошибки веб‑сервера (HTTP-коды 4xx, 5xx):'
+ grep -E ' "(4|5)[0-9][0-9] "' /tmp/nginx-report/recent.log
+ awk '{print $9, $7}'
+ sort
+ uniq -c
+ sort -nr
+ echo ''
+ echo '4. Все HTTP‑коды ответов и их количество:'
+ awk '{print $9}' /tmp/nginx-report/recent.log
+ grep -E '^[1-5][0-9][0-9]$'
+ sort
+ uniq -c
+ sort -nr
+ command -v mail
+ mail -s 'Nginx Report: 2025-12-08 14:00' -r goryacheva@bazis.vrn.ru m.guseva@kalinaoil.pro
+ rm -f /tmp/nginx-report/lock

```
![Image alt](https://github.com/bezzzhizni-coder/DZ09Bash/blob/7db62c3967fe63690156af9edd9d9c818a548689/mailreport.PNG)
