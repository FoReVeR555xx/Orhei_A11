


## Безопасное управление пользователями через Supabase Edge Function

Функция `supabase/functions/admin-user/index.ts` изменяет пользователей через Supabase Admin API. `SUPABASE_SERVICE_ROLE_KEY` **никогда не помещается в `config.js`, HTML или JavaScript браузера**.

### 1. Что находится в `config.js`

Только публичные данные проекта:

- `url` — URL проекта Supabase.
- `publishableKey` — Publishable/anon key. Его допустимо видеть в браузере при включённом RLS.

### 2. Что нужно задать в Supabase

В Supabase Dashboard откройте **Project Settings → API** и найдите **Secret / service_role key** (название зависит от версии панели).

Этот секрет нужен Edge Function. Не вставляйте его в `config.js`.

Задайте его как секрет Edge Function с именем:

`SUPABASE_SERVICE_ROLE_KEY`

`SUPABASE_URL` функция получает из окружения Supabase; вручную помещать URL в код не требуется.

### 3. SQL перед первым использованием

Откройте **SQL Editor** в Supabase и выполните актуальный `supabase/schema.sql` из этого проекта.

Для существующей базы особенно важно, чтобы выполнились:

```sql
alter table public.profiles add column if not exists role text not null default 'user';
drop constraint if exists profiles_role_check on public.profiles;
alter table public.profiles add constraint profiles_role_check check (role in ('user','admin'));
update public.profiles set role = 'admin' where lower(login) = 'admin';
```

После этого только профиль с `role = 'admin'` и активным статусом может вызывать административную Edge Function.

### 4. Деплой функции

Из корня проекта Supabase CLI:

```bash
supabase functions deploy admin-user
```

Не добавляйте `--no-verify-jwt`: функция должна оставаться защищённой авторизацией Supabase.

### 5. Как работает изменение пользователя

Браузер вызывает:

`admin-user`

и передаёт только данные операции. Edge Function получает текущий JWT, проверяет пользователя и роль `admin`, а затем с серверным `SUPABASE_SERVICE_ROLE_KEY` выполняет:

- изменение логина;
- изменение пароля;
- изменение видимого имени;
- изменение группы;
- изменение статуса;
- изменение permissions;
- создание и удаление пользователей.

Пароли не сохраняются в `profiles`, `localStorage` или журнале действий.

### 6. Важно

Никогда не публикуйте следующие секреты в GitHub или `config.js`:

- `service_role` key;
- Secret API key;
- пароль базы данных;
- другие секреты проекта.

Если секрет уже случайно был опубликован, его нужно немедленно заменить/отозвать в Supabase.
