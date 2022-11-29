Задача 2. Кэширующий DNS сервер

Сервер получает от клиента запрос и выполняет его разрешение.
Получив ответ от старшего сервера, разбирает пакет и извлекает из него информацию обо всех полях.
Полученная информация записывается в кэш и при повторном запросе от клиента сервер возвращает необходимую информацию уже из кэша.
При этом кэш регулярно обновляется: из него удаляются "просроченные" записи.

Запуск скрипта:
python main.py

Примеры запросов:
nslookup type=A yandex.com 127.0.0.1
nslookup type=NS yandex.ru 127.0.0.1

