# px-manager
Proxy info manager

## Client setup

Prefer configuration subscriptions: use [BrowserMegaProxy](https://github.com/andre487/BrowserMegaProxy)
for Chrome and Firefox, and [AndroidMegaProxy](https://github.com/andre487/AndroidMegaProxy)
for Android. The authenticated `/doc` page contains setup instructions; importing a
MegaProxy JSON file is the fallback.

The current `~/MyProjects/ansible-inventory/mega-proxy-inventory.yml` configures:

- Primary URL: `https://pxc-ru.jethelix.ru/api/config`.
- Fallback URL: `https://pxc-kz.jethelix.ru/api/config`.
- HTTPS Basic Auth: the user's PX Manager login and password (`users.https`).
- Automatic updates every 60 minutes.

These feeds are deployed by `~/MyProjects/MegaProxyServer/`; see its
[configuration API guide](https://github.com/andre487/MegaProxyServer/blob/main/docs/ru/config-api.md).
Endpoints, ports, paths and intervals come from `hosts.*.services.config_api`.
Client preferences come from `settings.client_config` and per-user `client_config`;
`client_config.subscription` may override `intervalMinutes` and `enabled`, while the
server manages URLs and credentials. Apply inventory changes to every affected API host
(and affected proxy hosts when changing users or services). Deploy PX Manager again to
refresh its `subscription.json`. Keep the URLs in `/doc` in sync when endpoints change.

## MegaProxy export

`/api/generate/mega-proxy` first requests a MegaProxy v8 configuration from the configured
subscription URLs in order, using the logged-in user's proxy credentials as HTTPS Basic Auth.
The first JSON response is returned as formatted JSON without validating its configuration.
Requests verify TLS certificates,
reject redirects, time out after five seconds per source, and limit responses to 1 MiB.
If every source fails or returns unparsable JSON, the existing local generator is used.

Locally generated profile IDs are
deterministic and do not include the endpoint or credentials, so importing a newly generated file
updates existing profiles and adds new servers without duplicating them. Set a unique, immutable
`profile_id` on each `hosts.json` entry; its title is used as a compatibility fallback. Profiles
removed from px-manager are offered for optional removal by MegaProxy during the next import.

The deploy playbook builds `subscription.json` from enabled `hosts.*.services.config_api`
entries in the MegaProxy inventory. The first URL is the subscription source; the remaining
URLs are fallbacks (eight sources maximum). The interval comes from the first service's
`interval_minutes`, defaulting to 60 minutes. MegaProxy exports include this subscription
with the same login and password as the proxy profiles. Without configuration API hosts
or a local `subscription.json`, exports omit the subscription.

Run tests with `uv run --locked python -m unittest discover -s tests`.
The schema in `tests/schemas/megaproxy-v8.schema.json` is copied unchanged from
[MegaProxyConfig](https://github.com/andre487/MegaProxyConfig/blob/8cb2d57cb1641fd97446b4ffd18ef6dcdad618dd/schemas/megaproxy-v8.schema.json).
To update it, copy the upstream schema and update this commit reference.

## Локальный запуск и деплой

На странице проверки прокси System и Cloudflare запрашиваются независимо и
окрашиваются каждый по своему результату. Успешные DNS-ответы кешируются по домену и
резолверу в общем LRU-кеше на час; ошибки не кешируются.

Локальная среда и запуск управляются uv:

```sh
uv sync --locked
uv run --locked python main.py --host 127.0.0.1 --port 8888
uv run --locked python -m unittest discover -s tests
```

Для первого тестового стенда создайте каталог `data` и выполните
`uv run --locked python -m tools.generate_test_data`. Команда перезаписывает
тестовых пользователей и список прокси, поэтому не запускайте её поверх своей конфигурации.

Деплой: `tools/deploy.sh`. Нужны Ansible с коллекцией `ansible.posix` и локальный rsync;
инвентарь и SSH-параметры берутся из окружения согласно `tools/deploy.sh`.
Синхронизируются файлы приложения, шаблоны, статика, lock-файл и служебные Python-скрипты;
правила находятся в `ansible/rsync-filter`. Новые корневые Python-модули добавляются
автоматически, удалённые файлы удаляются и на сервере. Локальные данные и секреты
в синхронизацию не входят.

На сервере исходники, venv и установленный uv интерпретатор находятся в `/opt/px-manager/`.
Ansible обновляет окружение через `uv sync --locked --no-dev`; systemd запускает Python
из этого venv. При изменениях сервис перезапускается. После проверки HTTP-ответа удаляется
старый каталог бинаря; старые сборки и venv внутри каталога исходников очищаются синхронизацией.
Конфигурация в `/etc/px-manager`, данные, логи и постоянное состояние хранятся отдельно.

При истечении сессии JS-запросы отправляют на вход с текущим адресом в `retpath`.
После входа сервер возвращает на этот адрес. Принимаются только локальные абсолютные пути;
внешние URL, управляющие символы и закодированные обходы отклоняются с возвратом на `/`.

## Репутация выходного IP

Отдельная страница `/lookup` доступна после входа через ссылку «Проверка IP или домена».
Введите IPv4, IPv6 или домен без схемы URL, порта и пути. Для домена выводятся ответы
системного DNS и Cloudflare, затем репутация найденных адресов без дублей.
Лимит проверки адресов за один запрос задаётся в `reputation.py`; остальные адреса можно
проверить отдельно. Используется общий кеш репутации со страницей прокси.
Яндекс здесь не вызывается, поскольку его endpoint проверяет IP запроса, а не заданный адрес.

На странице проверки прокси кнопка «Репутация IP» рядом с выходным адресом открывает
результаты Яндекса, Cloudflare Radar, ProxyCheck, IPQualityScore и ipapi.is. Radar показывает
организацию — оператора сети и ASN, а не оценку риска. Запросы начинаются
при открытии диалога. Отсутствующий ключ и ошибка сервиса отображаются отдельно от
отрицательного результата проверки. Оценки разных сервисов не складываются в общий балл:
обнаружение VPN и жалобы на злоупотребления — разные признаки.

### Как получить ключи

1. **ProxyCheck:** откройте [Dashboard](https://proxycheck.io/dashboard/), нажмите
   Register, зарегистрируйтесь по email и скопируйте API key из кабинета. Нужен ключ
   обычного API проверки IP, а не отдельное включение Dashboard API.
   [Документация](https://proxycheck.io/api/).
2. **IPQualityScore:** зарегистрируйтесь на [IPQS](https://www.ipqualityscore.com/),
   откройте Dashboard и раздел API Keys, создайте ключ для Proxy & VPN Detection API.
   [Управление ключами и авторизация](https://www.ipqualityscore.com/documentation/about-ipqs-apis/submitting-data-to-ipqs-apis).
3. **ipapi.is:** создайте [аккаунт](https://ipapi.is/), откройте Dashboard и скопируйте
   API key. Ключ нужен для полей VPN, proxy, Tor, datacenter и abuser: анонимный ответ
   их не содержит. [Документация](https://ipapi.is/developers.html).
4. **Яндекс:** ключ не требуется. Проверка выполняет POST через выбранный HTTPS-прокси
   и читает `X-Yandex-EU-Request`: `1` — VPN обнаружен, `0` — не обнаружен,
   другое значение или отсутствие заголовка — неизвестный результат. Это
   недокументированный контракт из `ExternalVpnCheck.md`, он может измениться.

Тариф и доступную квоту проверяйте в кабинетах сервисов перед получением ключей.

Для **Cloudflare Radar** откройте [API Tokens](https://dash.cloudflare.com/profile/api-tokens),
создайте Custom Token с правом Account → Radar → Read для своего аккаунта.
Сохраните токен в `~/.my-tokens/cloudflare-radar` с правами `0600`.
[Инструкция Radar](https://developers.cloudflare.com/radar/get-started/first-request/).

### Подключение

Создайте `reputation.json` в каталоге, указанном через `--config-dir` (рядом с `hosts.json`):

```json
{
  "cloudflare": "YOUR_CLOUDFLARE_RADAR_TOKEN",
  "proxycheck": "YOUR_PROXYCHECK_KEY",
  "ipqs": "YOUR_IPQS_KEY",
  "ipapi": "YOUR_IPAPI_KEY"
}
```

Оставьте ненужные ключи пустыми или уберите их. Ограничьте чтение файла пользователем
PX Manager (`chmod 600 reputation.json`) и перезапустите приложение. Файл исключён из Git;
ключи не передаются в браузер. Запросы к четырём API идут с сервера с явно указанным
выходным IP; только запрос Яндекса обязательно идёт через проверяемый прокси.

Для деплоя храните ключи в `px_manager_reputation_keys` в MegaProxy inventory:
поля `cloudflare`, `proxycheck`, `ipqs`, `ipapi`, каждое значение — строка `!vault` с текущим паролем
Ansible Vault. `tools/deploy.sh` уже подключает этот inventory и использует
`ANSIBLE_VAULT_PASSWORD_FILE` либо запрашивает пароль. Playbook создаёт
`/etc/px-manager/reputation.json` с владельцем `px-manager` и правами `0600`, скрывает
содержимое из логов/diff и перезапускает сервис при изменении файла. Локальный JSON
при деплое не копируется. Если переменная не задана, существующий файл на сервере сохраняется.

Ключ должен быть одной строкой без пробелов и переносов внутри. Если сайт разбивает его
при копировании, скопируйте только сам ключ и сохраните через
`pbpaste | tr -d '[:space:]' > ~/.my-tokens/ipqualityscore`, затем ограничьте права
`chmod 600 ~/.my-tokens/ipqualityscore`.

Результаты хранятся в общем для процесса LRU-кеше: до 1024 записей «сервис + IP + ключ»,
24 часа с момента успешной проверки. Повторное чтение продлевает только приоритет LRU,
но не срок. Одновременные проверки одной записи объединяются. Ошибки, неизвестные
ответы и отсутствующие ключи не кешируются. Время проверки и использование кеша видны
в диалоге. После перезапуска кеш пуст; при нескольких процессах у каждого свой кеш.
Яндекс проверяет текущий маршрут прокси: при смене выходного IP обновите страницу.

## Соединение с HTTPS-прокси

На странице `/health` результат Request показывает согласованные HTTP и TLS именно
между PX Manager и прокси. Выходной IP определяется сначала через Cloudflare trace,
затем через ifconfig.me, ipify и icanhazip при ошибках предыдущих источников.
Отдельные строки HTTP/2 и HTTP/3 проверяют работу CONNECT с принудительным протоколом
без переключения на другой; их ошибки не меняют результат обычного Request.
Для прокси с `http3_enabled` сначала используется HTTP/3;
при таймауте QUIC выполняется подключение по TCP с ALPN HTTP/2 или HTTP/1.1.
Ошибки сертификата и авторизации не запускают этот fallback.
Строка «Сертификат» показывает владельца, издателя и срок действия сертификата этого
же соединения; дата начала действия и SHA-256 доступны во всплывающей подсказке.

## Замер скорости прокси

На странице `/health` откройте «Замер скорости», выберите протокол и объём и нажмите
«Начать». Проверяется маршрут с сервера PX Manager через выбранный прокси к
`h3.speed.cloudflare.com`: метаданные из `/cdn-cgi/trace`, загрузка `/__down` и отправка
`/__up`. Показываются выходной IP, согласованный протокол, медиана трёх проб задержки
до заголовков ответа и скорости в Мбит/с. Выбранный объём передаётся в каждую сторону.

HTTP/2 и HTTP/1.1 используют HTTPS CONNECT либо SOCKS5. HTTP/3 использует QUIC внутри
MASQUE CONNECT-UDP; переключения на другой протокол или прямой выход при ошибке нет.
В локальном `hosts.json` включайте `http3_enabled` только для endpoint с MASQUE на том же
hostname и порту. Ansible берёт этот признак из `services.https.http3` для прямых маршрутов;
серверные SNI-цепочки его не получают. Для MTProxy замер Cloudflare недоступен.

Кнопка «Остановить», закрытие диалога и уход со страницы отменяют запрос и соединения.
Результаты приходят по этапам, не кешируются; уже полученные метрики сохраняются при
ошибке следующего этапа. Одновременно в одном процессе запускается один замер.
Клиенты реализованы на Python: HTTPX для HTTP/2 и aioquic для HTTP/3, с проверкой
сертификатов прокси и Cloudflare. После обновления зависимостей выполните `uv sync --locked`.
