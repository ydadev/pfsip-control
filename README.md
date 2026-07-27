# pfSIP Control

Локальный веб-портал для управления IP/CIDR-списками, которые pfSense
использует как `URL Table Alias`.

![Логотип pfSIP Control](logo.svg)

## Возможности

- авторизация администратора;
- создание, редактирование и удаление нескольких списков;
- отдельный URL с токеном для каждого списка;
- проверка и нормализация IPv4/IPv6 CIDR;
- объединение пересекающихся сетей;
- история публикаций в SQLite;
- CSRF-защита и серверные сессии;
- запуск через systemd от отдельного пользователя;
- ограничение доступа локальными сетями через Nginx;
- отсутствие сторонних Python-зависимостей.

Портал не редактирует `config.xml` и не хранит пароль от pfSense. Маршрутизатор
самостоятельно загружает опубликованные текстовые таблицы.

## Требования

- Ubuntu 24.04;
- Python 3.12 или новее;
- Nginx;
- systemd;
- pfSense с сетевым доступом к порталу.

## Установка

Установите Nginx:

```bash
sudo apt update
sudo apt install -y nginx
```

Скопируйте файлы проекта:

```bash
scp app.py route-portal.service nginx.conf deploy.sh logo.svg \
  ubuntu@SERVER:/tmp/
```

Для первоначального импорта можно передать список сетей:

```bash
scp my-routes.txt ubuntu@SERVER:/tmp/initial-routes.txt
```

Запустите установку с отдельным паролем администратора:

```bash
ssh ubuntu@SERVER
sudo env ROUTE_PORTAL_ADMIN_PASSWORD='CHANGE_THIS_PASSWORD' \
  bash /tmp/deploy.sh
```

Проверка:

```bash
systemctl status route-portal
systemctl status nginx
curl http://127.0.0.1:8080/health
```

По умолчанию:

- логин портала: `admin`;
- приложение слушает `127.0.0.1:8080`;
- Nginx слушает TCP/80;
- данные находятся в `/var/lib/route-portal`;
- переменные окружения хранятся в `/etc/route-portal.env`.

## Разрешённые сети

Пример `nginx.conf` разрешает доступ из:

```text
10.10.8.0/21
10.45.0.0/21
```

Измените сети под свою инфраструктуру:

```nginx
allow 10.10.8.0/21;
allow 10.45.0.0/21;
deny all;
```

После изменения:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## Работа со списками

После входа портал показывает каталог списков. Для каждого списка можно:

1. задать название, идентификатор и описание;
2. добавить адреса и CIDR-сети;
3. нажать **Проверить и опубликовать**;
4. скопировать URL для pfSense;
5. удалить больше не используемый список.

Пример:

```text
8.8.8.8/32
91.108.4.0/22
149.154.160.0/20
```

При вводе допускаются комментарии:

```text
10.10.12.23/32 # workstation
```

Комментарии не попадают в опубликованный файл.

## URL Table Alias в pfSense

Откройте:

```text
Firewall → Aliases → URLs → Add
```

Основной список:

```text
Name: ROUTE_VIA_AMNEZIA
Type: URL Table (IPs)
URL: URL списка маршрутов из портала
Update Frequency: 1
```

Исключения:

```text
Name: AMNEZIA_BYPASS
Type: URL Table (IPs)
URL: URL списка исключений из портала
Update Frequency: 1
```

Проверить загруженные адреса можно в:

```text
Diagnostics → Tables
```

## Policy-based routing

Пример сети:

```text
LAN:             10.10.8.0/21
WireGuard:       10.45.0.0/21
Gateway:         10.10.11.211
Gateway name:    amnezia
Обычный gateway: 02_WAN
```

Правила LAN выше общего разрешающего правила:

```text
1. Source: AMNEZIA_BYPASS
   Destination: ROUTE_VIA_AMNEZIA
   Gateway: 02_WAN

2. Source: LAN net
   Destination: ROUTE_VIA_AMNEZIA
   Gateway: amnezia
```

Правила WireGuard:

```text
1. Source: AMNEZIA_BYPASS
   Destination: ROUTE_VIA_AMNEZIA
   Gateway: default

2. Source: 10.45.0.0/21
   Destination: ROUTE_VIA_AMNEZIA
   Gateway: amnezia
```

## Gateway в той же LAN

Если дополнительный gateway находится в одной сети с клиентами, без SNAT
возникает асимметричная маршрутизация:

```text
запрос: клиент → pfSense → gateway
ответ:  gateway → клиент напрямую
```

Симптомы: медленные загрузки, повторные TCP SYN, состояния
`SYN_SENT:CLOSED`, нестабильная работа Telegram и UDP/QUIC.

Выберите:

```text
Firewall → NAT → Outbound → Hybrid Outbound NAT
```

Добавьте правила:

```text
Interface:   LAN
Source:      10.10.8.0/21
Destination: ROUTE_VIA_AMNEZIA
Translation: Interface address

Interface:   LAN
Source:      10.45.0.0/21
Destination: ROUTE_VIA_AMNEZIA
Translation: Interface address
```

SNAT заставляет дополнительный gateway возвращать ответы через pfSense.

## MTU и MSS

Если MTU туннеля равен 1420, задайте на LAN:

```text
Interfaces → LAN → MSS: 1420
```

pfSense создаст:

```text
IPv4 max-mss 1380
IPv6 max-mss 1360
```

Проверить MTU из Windows:

```powershell
ping -f -l 1392 8.8.8.8
ping -f -l 1393 8.8.8.8
```

Полезная нагрузка 1392 плюс 28 байт заголовков соответствует MTU 1420.

## Обновление и резервное копирование

## Кнопка «Опубликовать и обновить pfSense»

Портал умеет после сохранения списка немедленно обновить соответствующий
`URL Table`-алиас. Для списка укажите имя алиаса, например
`ROUTE_VIA_AMNEZIA` или `AMNEZIA_BYPASS`.

Соединение выполняется отдельным SSH-ключом. Ключ на pfSense запускает только
ограниченную команду обновления URL Table и не даёт порталу произвольный shell.

На pfSense установите `pfsense-refresh-command.sh` с владельцем `root` и правами
`0755`, затем добавьте публичный ключ портала в `authorized_keys`:

```text
restrict,command="/usr/local/sbin/pfsense-refresh-command" ssh-ed25519 AAAA...
```

На сервере портала храните закрытый ключ и `known_hosts` в каталоге
`/etc/route-portal-ssh`, доступном только `root:routeportal`, и добавьте в
`/etc/route-portal.env`:

```text
PFSENSE_REFRESH_HOST=10.10.10.254
PFSENSE_REFRESH_USER=admin
PFSENSE_REFRESH_KEY=/etc/route-portal-ssh/id_ed25519
PFSENSE_REFRESH_KNOWN_HOSTS=/etc/route-portal-ssh/known_hosts
```

После изменения переменных перезапустите службу:

```bash
sudo systemctl restart route-portal
```

Перед обновлением:

```bash
sudo cp -a /opt/route-portal /opt/route-portal.backup
sudo cp -a /var/lib/route-portal/portal.db \
  /var/lib/route-portal/portal.db.backup
```

Обновление приложения:

```bash
sudo install -o root -g root -m 0644 app.py /opt/route-portal/app.py
sudo systemctl restart route-portal
```

Сохраняйте резервные копии:

```text
/var/lib/route-portal/portal.db
/var/lib/route-portal/public/
/etc/route-portal.env
/etc/nginx/sites-available/route-portal
```

## Безопасность

- не публикуйте `/etc/route-portal.env`;
- не храните SSH/root-пароли в репозитории;
- используйте отдельный пароль портала;
- ограничивайте доступ через Nginx и firewall;
- настройте HTTPS для постоянной эксплуатации;
- считайте токены URL секретными.

## Тесты

```bash
python3 -m unittest -v
```

Проверка службы:

```bash
curl -f http://127.0.0.1:8080/health
```

## Лицензия

MIT — см. [LICENSE](LICENSE).
