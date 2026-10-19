import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { ...corsHeaders, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
})
const positiveEnv = (name: string, fallback: number) => {
  const n = Number(Deno.env.get(name))
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders })
  if (req.method !== 'POST') return json({ error: 'Method not allowed' }, 405)
  try {
    const url = Deno.env.get('SUPABASE_URL')
    const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')
    if (!url || !serviceKey) return json({ error: 'На сервере не настроены Supabase secrets' }, 500)
    const token = (req.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '').trim()
    if (!token) return json({ error: 'Требуется авторизация' }, 401)
    const admin = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } })
    const { data: authData, error: authError } = await admin.auth.getUser(token)
    if (authError || !authData.user) return json({ error: 'Сессия недействительна' }, 401)
    const { data: profile, error: profileError } = await admin.from('profiles')
      .select('login,group_name,status').eq('id', authData.user.id).maybeSingle()
    if (profileError) return json({ error: 'Не удалось проверить права владельца' }, 500)
    const login = String(profile?.login || authData.user.email?.split('@')[0] || '').toLowerCase()
    const group = String(profile?.group_name || '').trim().toLocaleLowerCase('ru-RU')
    const owner = profile?.status !== 'Неактивен' && (login === 'admin' || ['владельцы','владелец','администраторы','администратор','owners','owner','admins','admin'].includes(group))
    if (!owner) return json({ error: 'Статистика хранилища доступна только владельцу сайта' }, 403)
    const { data, error } = await admin.rpc('get_bomba_storage_usage')
    if (error) return json({ error: 'Не удалось прочитать статистику: ' + error.message }, 500)
    const row = Array.isArray(data) ? data[0] : data
    if (!row) return json({ error: 'Функция статистики не вернула данные' }, 500)
    // Defaults are Free-tier reference quotas. Override with project secrets for another plan.
    const databaseLimit = positiveEnv('DATABASE_LIMIT_BYTES', 500 * 1000 * 1000)
    const storageLimit = positiveEnv('STORAGE_LIMIT_BYTES', 1000 * 1000 * 1000)
    return json({
      database_bytes: Number(row.database_bytes) || 0,
      storage_bytes: Number(row.storage_bytes) || 0,
      database_limit_bytes: databaseLimit,
      storage_limit_bytes: storageLimit,
      limits_are_defaults: !Deno.env.get('DATABASE_LIMIT_BYTES') && !Deno.env.get('STORAGE_LIMIT_BYTES'),
      sections: Array.isArray(row.sections) ? row.sections : [],
      buckets: Array.isArray(row.buckets) ? row.buckets : [],
      folders: Array.isArray(row.folders) ? row.folders : [],
      measured_at: row.measured_at || new Date().toISOString(),
      next_refresh_at: row.next_refresh_at || new Date(Date.now() + 5 * 60 * 1000).toISOString(),
    })
  } catch (e) {
    console.error('storage-usage error', e)
    return json({ error: e instanceof Error ? e.message : 'Внутренняя ошибка' }, 500)
  }
})
