import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, 'Content-Type': 'application/json' } })

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)

  const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!
  const SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  const admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, { auth: { persistSession: false } })

  try {
    const authHeader = req.headers.get('Authorization') || ''
    const token = authHeader.replace(/^Bearer\s+/i, '')
    if (!token) return json({ error: 'Необходима авторизация' }, 401)

    const { data: callerData, error: callerError } = await admin.auth.getUser(token)
    if (callerError || !callerData.user) return json({ error: 'Недействительная сессия' }, 401)
    const caller = callerData.user

    // The first admin account uses the Bomba convention admin@bomba.local.
    // For subsequent calls, also require an admin profile or admin marker.
    const { data: callerProfile } = await admin.from('profiles').select('login,status').eq('id', caller.id).maybeSingle()
    const callerLogin = callerProfile?.login || String(caller.email || '').split('@')[0]
    const isAdmin = callerLogin === 'admin' && callerProfile?.status !== 'Неактивен'
    if (!isAdmin) return json({ error: 'Недостаточно прав' }, 403)

    const body = await req.json()
    const action = String(body.action || '')
    const normalizeLogin = (value: unknown) => String(value || '').trim().toLowerCase()
    const emailForLogin = (login: string) => `${login}@bomba.local`
    const validLogin = (login: string) => /^[a-z0-9._-]{2,40}$/i.test(login)

    if (action === 'create') {
      const login = normalizeLogin(body.login)
      const name = String(body.name || '').trim()
      const password = String(body.password || '')
      const group = String(body.group || 'Сотрудники').trim()
      const status = String(body.status || 'Активен')
      const permissions = Array.isArray(body.permissions) ? body.permissions : []
      if (!validLogin(login) || !name || password.length < 6) return json({ error: 'Проверьте логин, название и пароль (минимум 6 символов)' }, 400)
      if (login === 'admin') return json({ error: 'Логин admin уже зарезервирован' }, 400)

      const { data: created, error } = await admin.auth.admin.createUser({
        email: emailForLogin(login), password, email_confirm: true,
        user_metadata: { display_name: name, group_name: group, permissions }
      })
      if (error || !created.user) return json({ error: error?.message || 'Не удалось создать пользователя' }, 400)

      const { error: profileError } = await admin.from('profiles').upsert({
        id: created.user.id, login, display_name: name, group_name: group, status, permissions, updated_at: new Date().toISOString()
      })
      if (profileError) {
        await admin.auth.admin.deleteUser(created.user.id)
        return json({ error: profileError.message }, 400)
      }
      return json({ user: { id: created.user.id, name, login, group, status, permissions } })
    }

    if (action === 'update') {
      let userId = String(body.userId || '')
      const requestedLogin = normalizeLogin(body.login)
      let currentQuery = admin.from('profiles').select('*')
      if (userId && /^[0-9a-f-]{36}$/i.test(userId)) currentQuery = currentQuery.eq('id', userId)
      else if (requestedLogin) currentQuery = currentQuery.eq('login', requestedLogin)
      else return json({ error: 'Не указан пользователь' }, 400)
      const { data: current, error: currentError } = await currentQuery.maybeSingle()
      userId = current?.id || userId
      if (currentError) return json({ error: currentError.message }, 400)
      if (!current) return json({ error: 'Профиль пользователя не найден. Создайте профиль заново.' }, 404)
      if (current.login === 'admin' && normalizeLogin(body.login) !== 'admin') return json({ error: 'Главный логин admin нельзя переименовать' }, 400)

      const login = normalizeLogin(body.login || current.login)
      const name = String(body.name ?? current.display_name).trim()
      const group = String(body.group ?? current.group_name).trim()
      const status = String(body.status ?? current.status)
      const permissions = current.login === 'admin' ? (Array.isArray(current.permissions) ? current.permissions : []) : (Array.isArray(body.permissions) ? body.permissions : [])
      const password = body.password ? String(body.password) : ''
      if (!validLogin(login) || !name) return json({ error: 'Некорректные данные пользователя' }, 400)
      if (password && password.length < 6) return json({ error: 'Пароль должен содержать минимум 6 символов' }, 400)

      const authUpdate: Record<string, unknown> = { email: emailForLogin(login), user_metadata: { display_name: name, group_name: group, permissions } }
      if (password) authUpdate.password = password
      const { error: authError } = await admin.auth.admin.updateUserById(userId, authUpdate)
      if (authError) return json({ error: authError.message }, 400)

      const { error: profileError } = await admin.from('profiles').update({ login, display_name: name, group_name: group, status, permissions, updated_at: new Date().toISOString() }).eq('id', userId)
      if (profileError) return json({ error: profileError.message }, 400)
      return json({ user: { id: userId, name, login, group, status, permissions } })
    }

    if (action === 'delete') {
      let userId = String(body.userId || '')
      const requestedLogin = normalizeLogin(body.login)
      if (!userId && !requestedLogin) return json({ error: 'Не указан пользователь' }, 400)
      let currentQuery = admin.from('profiles').select('id,login').limit(1)
      if (userId && /^[0-9a-f-]{36}$/i.test(userId)) currentQuery = currentQuery.eq('id', userId)
      else if (requestedLogin) currentQuery = currentQuery.eq('login', requestedLogin)
      const { data: current } = await currentQuery.maybeSingle()
      if (!current) return json({ error: 'Пользователь не найден' }, 404)
      userId = current.id
      if (userId === caller.id) return json({ error: 'Нельзя удалить текущего администратора' }, 400)
      if (!current) return json({ error: 'Пользователь не найден' }, 404)
      if (current.login === 'admin') return json({ error: 'Главного администратора удалить нельзя' }, 400)
      const { error } = await admin.auth.admin.deleteUser(userId)
      if (error) return json({ error: error.message }, 400)
      return json({ ok: true })
    }

    if (action === 'sync') {
      const { data: profiles, error: profilesError } = await admin.from('profiles').select('id,login,display_name,group_name,status,permissions,created_at,updated_at').order('login')
      if (profilesError) return json({ error: profilesError.message }, 400)
      return json({ profiles: profiles || [] })
    }

    return json({ error: 'Неизвестное действие' }, 400)
  } catch (e) {
    console.error(e)
    return json({ error: e instanceof Error ? e.message : 'Внутренняя ошибка' }, 500)
  }
})
