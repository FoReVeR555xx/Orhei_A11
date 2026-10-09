import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers':
    'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      'Content-Type': 'application/json',
    },
  })

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  if (req.method !== 'POST') {
    return json({ error: 'Method not allowed' }, 405)
  }

  try {
    // ============================================================
    // SECRETS
    // ============================================================

    const SUPABASE_URL = Deno.env.get('SUPABASE_URL')
    const SERVICE_ROLE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')

    if (!SUPABASE_URL) {
      console.error('SUPABASE_URL отсутствует')
      return json(
        { error: 'На сервере отсутствует SUPABASE_URL' },
        500,
      )
    }

    if (!SERVICE_ROLE_KEY) {
      console.error('SUPABASE_SERVICE_ROLE_KEY отсутствует')
      return json(
        { error: 'На сервере отсутствует SUPABASE_SERVICE_ROLE_KEY' },
        500,
      )
    }

    const admin = createClient(
      SUPABASE_URL,
      SERVICE_ROLE_KEY,
      {
        auth: {
          persistSession: false,
          autoRefreshToken: false,
        },
      },
    )

    // ============================================================
    // AUTHORIZATION
    // ============================================================

    const authHeader = req.headers.get('Authorization') || ''
    const token = authHeader
      .replace(/^Bearer\s+/i, '')
      .trim()

    if (!token) {
      return json(
        { error: 'Необходима авторизация' },
        401,
      )
    }

    const {
      data: callerData,
      error: callerError,
    } = await admin.auth.getUser(token)

    if (callerError || !callerData?.user) {
      console.error(
        'Ошибка проверки токена:',
        callerError,
      )

      return json(
        { error: 'Недействительная сессия' },
        401,
      )
    }

    const caller = callerData.user

    // ============================================================
    // ADMIN PROFILE
    // ============================================================

    const {
      data: callerProfile,
      error: callerProfileError,
    } = await admin
      .from('profiles')
      .select('id,login,status,permissions')
      .eq('id', caller.id)
      .maybeSingle()

    if (callerProfileError) {
      console.error(
        'Ошибка получения профиля администратора:',
        callerProfileError,
      )

      return json(
        { error: callerProfileError.message },
        500,
      )
    }

    const callerLogin =
      callerProfile?.login ||
      String(caller.email || '').split('@')[0]

    const isAdmin =
      String(callerLogin).toLowerCase() === 'admin' &&
      callerProfile?.status !== 'Неактивен'
    const callerPermissions = Array.isArray(callerProfile?.permissions)
      ? callerProfile.permissions.map((p: unknown) => String(p))
      : []
    const canManageUsers = isAdmin || (callerProfile?.status !== 'Неактивен' && callerPermissions.includes('users.manage'))

    if (!canManageUsers) {
      return json({ error: 'Недостаточно прав: требуется users.manage' }, 403)
    }

    // ============================================================
    // REQUEST
    // ============================================================

    let body: Record<string, any>

    try {
      body = await req.json()
    } catch {
      return json(
        { error: 'Некорректный JSON-запрос' },
        400,
      )
    }

    const action = String(body.action || '').trim()

    const normalizeLogin = (value: unknown) =>
      String(value || '')
        .trim()
        .toLowerCase()

    const emailForLogin = (login: string) =>
      `${login}@bomba.local`

    const validLogin = (login: string) =>
      /^[a-z0-9._-]{2,40}$/i.test(login)

    // ============================================================
    // CREATE
    // ============================================================

    if (action === 'create') {
      const login = normalizeLogin(body.login)
      const name = String(body.name || '').trim()
      const password = String(body.password || '')
      const group = String(
        body.group || 'Сотрудники',
      ).trim()
      const status = String(
        body.status || 'Активен',
      )

      const requestedPermissions = Array.isArray(body.permissions)
        ? body.permissions.map((p: unknown) => String(p))
        : []
      const permissions = isAdmin
        ? requestedPermissions
        : requestedPermissions.filter((p: string) => callerPermissions.includes(p))

      if (
        !validLogin(login) ||
        !name ||
        password.length < 6
      ) {
        return json(
          {
            error:
              'Проверьте логин, название и пароль (минимум 6 символов)',
          },
          400,
        )
      }

      if (login === 'admin') {
        return json(
          {
            error:
              'Логин admin уже зарезервирован',
          },
          400,
        )
      }

      const {
        data: created,
        error: createError,
      } = await admin.auth.admin.createUser({
        email: emailForLogin(login),
        password,
        email_confirm: true,
        user_metadata: {
          display_name: name,
          group_name: group,
          permissions,
        },
      })

      if (createError || !created?.user) {
        console.error(
          'Ошибка создания Auth пользователя:',
          createError,
        )

        return json(
          {
            error:
              createError?.message ||
              'Не удалось создать пользователя',
          },
          400,
        )
      }

      const {
        error: profileError,
      } = await admin
        .from('profiles')
        .upsert({
          id: created.user.id,
          login,
          display_name: name,
          group_name: group,
          status,
          permissions,
          updated_at: new Date().toISOString(),
        })

      if (profileError) {
        console.error(
          'Ошибка создания профиля:',
          profileError,
        )

        await admin.auth.admin.deleteUser(
          created.user.id,
        )

        return json(
          { error: profileError.message },
          400,
        )
      }

      return json({
        user: {
          id: created.user.id,
          name,
          login,
          group,
          status,
          permissions,
        },
      })
    }

    // ============================================================
    // UPDATE
    // ============================================================

    if (action === 'update') {
      let userId = String(
        body.userId || '',
      ).trim()

      const requestedLogin =
        normalizeLogin(body.login)

      let currentQuery = admin
        .from('profiles')
        .select('*')

      if (
        userId &&
        /^[0-9a-f-]{36}$/i.test(userId)
      ) {
        currentQuery =
          currentQuery.eq('id', userId)
      } else if (requestedLogin) {
        currentQuery =
          currentQuery.eq(
            'login',
            requestedLogin,
          )
      } else {
        return json(
          { error: 'Не указан пользователь' },
          400,
        )
      }

      const {
        data: current,
        error: currentError,
      } = await currentQuery.maybeSingle()

      if (currentError) {
        console.error(
          'Ошибка поиска пользователя:',
          currentError,
        )

        return json(
          { error: currentError.message },
          400,
        )
      }

      if (!current) {
        return json(
          {
            error:
              'Профиль пользователя не найден',
          },
          404,
        )
      }
      if (normalizeLogin(current.login) === 'admin' && !isAdmin) {
        return json({ error: 'Управлять главным администратором может только он сам' }, 403)
      }

      userId = current.id

      if (
        current.login === 'admin' &&
        normalizeLogin(body.login) !== 'admin'
      ) {
        return json(
          {
            error:
              'Главный логин admin нельзя переименовать',
          },
          400,
        )
      }

      const login = normalizeLogin(
        body.login || current.login,
      )

      const name = String(
        body.name ?? current.display_name,
      ).trim()

      const group = String(
        body.group ?? current.group_name,
      ).trim()

      const status = String(
        body.status ?? current.status,
      )

      const requestedPermissions = Array.isArray(body.permissions)
        ? body.permissions.map((p: unknown) => String(p))
        : Array.isArray(current.permissions)
          ? current.permissions
          : []
      const permissions = current.login === 'admin'
        ? (Array.isArray(current.permissions) ? current.permissions : [])
        : isAdmin
          ? requestedPermissions
          : requestedPermissions.filter((p: string) => callerPermissions.includes(p))

      const password = body.password
        ? String(body.password)
        : ''

      if (!validLogin(login) || !name) {
        return json(
          {
            error:
              'Некорректные данные пользователя',
          },
          400,
        )
      }

      if (
        password &&
        password.length < 6
      ) {
        return json(
          {
            error:
              'Пароль должен содержать минимум 6 символов',
          },
          400,
        )
      }

      const authUpdate: Record<
        string,
        unknown
      > = {
        email: emailForLogin(login),
        user_metadata: {
          display_name: name,
          group_name: group,
          permissions,
        },
      }

      if (password) {
        authUpdate.password = password
      }

      const {
        error: authError,
      } =
        await admin.auth.admin.updateUserById(
          userId,
          authUpdate,
        )

      if (authError) {
        console.error(
          'Ошибка изменения Auth пользователя:',
          authError,
        )

        return json(
          { error: authError.message },
          400,
        )
      }

      const {
        error: profileError,
      } = await admin
        .from('profiles')
        .update({
          login,
          display_name: name,
          group_name: group,
          status,
          permissions,
          updated_at: new Date().toISOString(),
        })
        .eq('id', userId)

      if (profileError) {
        console.error(
          'Ошибка изменения профиля:',
          profileError,
        )

        return json(
          { error: profileError.message },
          400,
        )
      }

      return json({
        user: {
          id: userId,
          name,
          login,
          group,
          status,
          permissions,
        },
      })
    }

    // ============================================================
    // DELETE
    // ============================================================

    if (action === 'delete') {
      const requestedLogin = normalizeLogin(body.login)
      const requestedId = String(body.userId || '').trim()
      let profile: Record<string, any> | null = null

      // Prefer the stable login from the UI. A stale UUID must not prevent
      // deletion of the intended account when the login still matches.
      if (requestedLogin) {
        const { data, error } = await admin
          .from('profiles')
          .select('*')
          .eq('login', requestedLogin)
          .maybeSingle()
        if (error) return json({ error: `Ошибка поиска профиля: ${error.message}` }, 500)
        profile = data
      }

      if (!profile && requestedId && /^[0-9a-f-]{36}$/i.test(requestedId)) {
        const { data, error } = await admin
          .from('profiles')
          .select('*')
          .eq('id', requestedId)
          .maybeSingle()
        if (error) return json({ error: `Ошибка поиска профиля: ${error.message}` }, 500)
        profile = data
      }

      if (!profile && !requestedLogin && !requestedId) {
        return json({ error: 'Не указан пользователь' }, 400)
      }

      if (profile?.login && normalizeLogin(profile.login) === 'admin') {
        return json({ error: 'Главного администратора удалить нельзя' }, 400)
      }

      let authUserId = String(profile?.id || '')
      const loginForLookup = requestedLogin || normalizeLogin(profile?.login)

      // Recover orphaned Auth accounts whose profile row is missing.
      if (!authUserId && requestedId && /^[0-9a-f-]{36}$/i.test(requestedId)) {
        authUserId = requestedId
      }
      if (!authUserId && loginForLookup) {
        const { data: usersPage, error: listError } = await admin.auth.admin.listUsers({ page: 1, perPage: 1000 })
        if (listError) return json({ error: `Не удалось найти Auth-пользователя: ${listError.message}` }, 500)
        const authMatch = usersPage.users.find(u => normalizeLogin(u.email) === emailForLogin(loginForLookup).toLowerCase())
        if (authMatch) authUserId = authMatch.id
      }

      if (!authUserId) {
        return json({ error: 'Пользователь не найден ни в profiles, ни в Supabase Auth' }, 404)
      }
      if (authUserId === caller.id) {
        return json({ error: 'Нельзя удалить текущую учётную запись администратора' }, 400)
      }

      // Remove profile first to avoid stale profile rows. If Auth deletion
      // fails, restore the profile so the account remains manageable.
      if (profile) {
        const { error: profileDeleteError } = await admin
          .from('profiles')
          .delete()
          .eq('id', profile.id)
        if (profileDeleteError) {
          return json({ error: `Не удалось удалить профиль: ${profileDeleteError.message}` }, 500)
        }
      }

      const { error: authDeleteError } = await admin.auth.admin.deleteUser(authUserId)
      if (authDeleteError) {
        if (profile) {
          const { error: restoreError } = await admin.from('profiles').upsert(profile)
          if (restoreError) {
            return json({ error: `Не удалось удалить Auth-пользователя: ${authDeleteError.message}. Также не удалось восстановить профиль: ${restoreError.message}` }, 500)
          }
        }
        return json({ error: `Не удалось удалить пользователя из Supabase Auth: ${authDeleteError.message}` }, 400)
      }

      return json({ ok: true, deletedUserId: authUserId, deletedLogin: profile?.login || loginForLookup || null })
    }

    // ============================================================
    // SYNC
    // ============================================================

    if (action === 'sync') {
      const {
        data: profiles,
        error: profilesError,
      } = await admin
        .from('profiles')
        .select(
          'id,login,display_name,group_name,status,permissions,created_at,updated_at',
        )
        .order('login')

      if (profilesError) {
        console.error(
          'Ошибка синхронизации:',
          profilesError,
        )

        return json(
          { error: profilesError.message },
          400,
        )
      }

      return json({
        profiles: profiles || [],
      })
    }

    // ============================================================
    // UNKNOWN ACTION
    // ============================================================

    return json(
      {
        error:
          `Неизвестное действие: ${action}`,
      },
      400,
    )
  } catch (e) {
    console.error(
      'UNHANDLED ERROR:',
      e,
    )

    return json(
      {
        error:
          e instanceof Error
            ? e.message
            : 'Внутренняя ошибка Edge Function',
      },
      500,
    )
  }
})
