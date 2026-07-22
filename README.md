[English](README.en.md)

Подробнее: https://github.com/vahellame/russia-whitelist-routing

Домены находящихся в белых списках российских сервисов, собранные в `geosite.dat` для роутинга Xray/V2Ray.

**Как формируются:** домены сгруппированы по сервисам и категориям в `data/`; `whitelist` объединяет все списки через `include:`. `domain-list-community` собирает их в `geosite.dat` — каждый файл доступен как `geosite:<имя>`.

## Списки

`whitelist` — всё сразу (включает все списки ниже).

**Сервисы:** `yandex`, `vk`, `ozon`, `x5`, `wildberries` и 

**Категории:** `category-finance`, `category-gov`, `category-media`, `category-medicine`, `category-payments`, `category-shopping`, `category-telecom`, `category-transport`, `category-video`

## Скачать

```
https://github.com/vahellame/russia-whitelist-geosite/releases/latest/download/geosite.dat
```