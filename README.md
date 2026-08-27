Основной проект: https://github.com/vahellame/russia-whitelist-routing

## Что это

Домены находящихся в белых списках РФ. Собираются в `geosite.dat` для Xray и в rule-set форматов `.srs`, `.mrs` и `.list` для sing-box, mihomo и Shadowrocket, отдельным набором на каждую категорию

К релизу прикладываются две контрольные суммы: `geosite.dat.sha256` с голым хешем на 64 символа, по которому INCY определяет, изменился ли файл ([подробнее](https://docs.incy.cc/routing/#геофайлы-оптимизированное-скачивание)), и `geosite.dat.sha256sum` в формате GNU coreutils

## Категории

Домены сгруппированы по сервисам и категориям в `data/`; `whitelist` объединяет все списки кроме `category-ads`, `category-public-dns` и `private`

`category-ads` включает в себя сгруппированные по провайдеру рекламу и трекеры. Взяты популярные из [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter), [HaGeZi Pro](https://github.com/hagezi/dns-blocklists#pro), [OISD Big](https://oisd.nl/), [Loyalsoldier](https://github.com/Loyalsoldier/v2ray-rules-dat)

`category-public-dns` включает в себя DoH- и HTTPDNS-резолверы, через них клиент резолвит домены сам, и правила роутинга и блокировки могут не примениться. Без доступа к ним он откатывается на DNS конфигурации

## Проверка

`scripts/check.py` прогоняет точные домены через [BSCHEKER API](https://bsbord.com/llms.txt) и показывает, у каких операторов они не отвечают

```sh
export BSCHEKER_TOKEN=bsk_live_...
python3 scripts/check.py              # весь whitelist
python3 scripts/check.py category-gov # отдельный список
```

`include:` разворачивается, проверяются только записи `full:`, по TCP и SNI и только через каналы с включённым белым списком. Списание с баланса аккаунта

`scripts/annotate.py` определяет, за какой защитой стоит каждый `full:` домен, и проставляет рядом атрибут

```sh
python3 scripts/annotate.py                 # все списки
python3 scripts/annotate.py category-gov    # отдельный список
```

Домен резолвится, адрес сверяется с анонсируемыми префиксами семи провайдеров из RIPEstat, рядом появляется `@ngenix`, `@ddosguard` и так далее. Префиксы кэшируются в `.cache` на сутки

## Намеренно не включено в whitelist

Заявлены Минцифры, но фактически в белых списках отсутствуют:

- ЛизаАлерт: `lizaalert.org`, `lizaalert.ru`
- Соловьёв Live: `soloviev.live`
- Рувики: `ruwiki.ru`

Также не в белых списках:

- `yandex.kz`, `yandex.kg`
- `2gis.kz`
