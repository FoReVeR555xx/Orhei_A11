# Bomba A11 — Supabase подключение

Эта версия использует Supabase Auth для входа и PostgreSQL для центрального состояния приложения.

## 1. SQL

В Supabase Dashboard → SQL Editor вставьте и выполните `supabase/schema.sql`.

## 2. Auth users

В Supabase → Authentication → Users создайте сотрудников. Для совместимости с текущим полем «Логин» используются внутренние email-адреса вида:

- `admin@bomba.local`
- `av@bomba.local`
- `kbt@bomba.local`
- `Haier@bomba.local`
- `Bosch@bomba.local`

В интерфейсе пользователь по-прежнему вводит только логин (`admin`, `av`, `kbt` и т.д.). Пароли хранятся Supabase Auth, а не в HTML/JavaScript.

Для продакшена можно позже перейти на реальные email-адреса.

## 3. Publishable key

`config.js` содержит только Project URL и publishable key. Publishable key предназначен для браузера, но безопасность данных обеспечивается RLS. Никогда не помещайте `sb_secret_...` / `service_role` в этот файл.

## 4. Данные

После входа приложение пытается загрузить центральное состояние из `app_state`. Если оно пустое, текущие локальные данные используются как первоначальный источник и отправляются в облако. Старый localStorage не удаляется автоматически.

## 5. GitHub Pages

Загрузите весь каталог на GitHub и включите Pages для ветки/каталога, где находится `index.html`. `config.js` должен быть опубликован вместе с frontend.

## Важно

Сейчас центральное хранилище сделано как переходный слой для существующего монолитного приложения: состояние приложения хранится в одной JSONB-записи. Для окончательной production-версии рекомендуется разнести сущности по отдельным PostgreSQL-таблицам и сделать отдельные RLS-политики для пользователей, сервисов, доставок, продаж, кошелька и логов.

## Управление пользователями через Supabase Auth

В проект добавлена Edge Function `supabase/functions/admin-user/index.ts`.
Она позволяет администратору Bomba создавать, изменять пароль/логин/группу/статус/права и удалять пользователей. `service_role` используется только внутри Edge Function и не попадает во frontend.

### Установка Edge Function

1. Установите Supabase CLI и выполните `supabase login`.
2. В каталоге проекта выполните `supabase link --project-ref ifcawjyumzzslhtcoeeh`.
3. Задайте секрет Edge Function (CLI обычно получает стандартный `SUPABASE_SERVICE_ROLE_KEY` автоматически для Edge Functions):
   `supabase secrets set SUPABASE_SERVICE_ROLE_KEY=ВАШ_SERVICE_ROLE_KEY`
4. Разверните функцию:
   `supabase functions deploy admin-user`
5. В Supabase Authentication отключите публичную регистрацию (Allow new users / Sign ups), если сотрудники должны создаваться только администратором.

После этого вкладка **Пользователи** в Bomba создаёт/изменяет/удаляет Auth-пользователей через функцию. Пароли никогда не сохраняются в `app_state`, `profiles`, HTML или localStorage.

### Важное

Технический email Supabase формируется автоматически как `<login>@bomba.local`, но сотрудник продолжает входить в Bomba обычным логином (`admin`, `av`, `kbt` и т. д.).
