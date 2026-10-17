import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import nodemailer from 'npm:nodemailer@6.9.16';

const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type' };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...cors, 'Content-Type': 'application/json' } });
const str = (v: unknown) => String(v ?? '');
const safe = (v: string) => v.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
function fill(template: string, values: Record<string,string>) { return template.replace(/\{(account|section|message)\}/g, (_, k) => values[k] ?? ''); }
function kindOf(n: any) { return n?.orderNotification ? 'productOrder' : (n?.serviceActId || str(n?.id).startsWith('ann-sa-')) ? 'serviceAct' : 'other'; }
function sectionOf(kind: string) { return kind === 'productOrder' ? 'Заказ товара' : kind === 'serviceAct' ? 'Сервис-Акт' : 'Уведомления'; }

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors });
  const expected = Deno.env.get('EMAIL_CRON_SECRET');
  if (!expected || req.headers.get('x-cron-secret') !== expected) return json({ error: 'Unauthorized' }, 401);
  const url = Deno.env.get('SUPABASE_URL')!, serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const gmailUser = Deno.env.get('GMAIL_SMTP_USER'), gmailPass = Deno.env.get('GMAIL_APP_PASSWORD');
  if (!url || !serviceKey || !gmailUser || !gmailPass) return json({ error: 'Missing server secrets' }, 500);
  const supabase = createClient(url, serviceKey, { auth: { persistSession: false } });
  const { data: row, error } = await supabase.from('app_state').select('payload').eq('id','main').maybeSingle();
  if (error) return json({ error: error.message }, 500);
  const payload = row?.payload ?? {}, settings = payload.siteSettings ?? {}, emailCfg = settings.emailNotifications ?? {};
  if (!emailCfg.enabled) return json({ ok: true, sent: 0, skipped: 0, errors: 0, reason: 'disabled' });

  // Keep the existing delay/read-state rules. Once notifications pass the delay and
  // remain unread, collect them per recipient and send one digest email per run.
  const delayMs = Math.max(1, Math.min(10080, Number(emailCfg.delayMinutes) || 60)) * 60000;
  const recipients: Record<string,string> = emailCfg.recipients ?? {};
  const templates = emailCfg.templates ?? {};
  const announcements = Array.isArray(payload.announcements) ? payload.announcements : [];
  const now = Date.now();
  const pendingByLogin = new Map<string, any[]>();
  const unreadByLogin = new Map<string, any[]>();
  let skipped = 0, errors = 0, sent = 0;

  // First collect all currently unread notifications per recipient. The 60-minute
  // rule is a trigger: once at least one unread notification has aged past the
  // delay, include the recipient's other unread notifications in the same digest,
  // even if those arrived more recently.
  for (const n of announcements) {
    const created = Number(n?.createdAt) || Date.parse(n?.createdAt || '') || 0;
    if (!n?.id || !created) continue;
    const logins = [...new Set((Array.isArray(n.recipients) ? n.recipients : []).map((x: unknown) => str(x).trim().toLowerCase()).filter(Boolean))];
    for (const login of logins) {
      const email = str(recipients[login]).trim();
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { skipped++; continue; }
      const readBy = Array.isArray(n.readBy) ? n.readBy.map((x: unknown) => str(x).toLowerCase()) : [];
      if (readBy.includes(login)) { skipped++; continue; }
      if (!unreadByLogin.has(login)) unreadByLogin.set(login, []);
      unreadByLogin.get(login)!.push({ notification: n, login, email });
      if (now - created >= delayMs) {
        // Presence of this marker means the delay condition is satisfied for this user.
        if (!pendingByLogin.has(login)) pendingByLogin.set(login, []);
      }
    }
  }
  // Once a recipient qualifies, send all of their unread notifications not already
  // sent, rather than only those whose individual timers have expired.
  for (const login of pendingByLogin.keys()) {
    const candidates = unreadByLogin.get(login) ?? [];
    const fresh: any[] = [];
    for (const item of candidates) {
      const { data: prior, error: lookupError } = await supabase.from('email_notification_sent').select('notification_id').eq('notification_id', str(item.notification.id)).eq('recipient_login', login).maybeSingle();
      if (lookupError) { errors++; continue; }
      if (prior) { skipped++; continue; }
      fresh.push(item);
    }
    pendingByLogin.set(login, fresh);
  }

  const transporter = nodemailer.createTransport({ host: 'smtp.gmail.com', port: 465, secure: true, auth: { user: gmailUser, pass: gmailPass } });
  for (const [login, candidates] of pendingByLogin) {
    // Claim every item first; the primary key prevents concurrent cron invocations
    // from including the same notification in multiple emails.
    const claimed: typeof candidates = [];
    for (const item of candidates) {
      const { error: claimError } = await supabase.from('email_notification_sent').insert({ notification_id: str(item.notification.id), recipient_login: login, recipient_email: item.email });
      if (claimError) { skipped++; continue; }
      claimed.push(item);
    }
    if (!claimed.length) continue;

    const kinds = [...new Set(claimed.map(item => kindOf(item.notification)))];
    const section = kinds.map(sectionOf).join(', ');
    const count = claimed.length;
    const lines = claimed.map((item, index) => {
      const n = item.notification, kind = kindOf(n), created = Number(n.createdAt) || Date.parse(n.createdAt || '') || 0;
      const when = created ? new Date(created).toLocaleString('ru-RU', { timeZone: 'Europe/Chisinau' }) : '';
      const values = { account: login, section: sectionOf(kind), message: str(n.message).trim() };
      const t = templates[kind] ?? {};
      const itemTemplate = str(t.body || 'Уведомление в разделе «{section}»:\n{message}');
      const itemBody = fill(itemTemplate, values);
      return `${index + 1}. ${sectionOf(kind)}${when ? ` — ${when}` : ''}\n${itemBody}`;
    });
    const values = { account: login, section, message: `${count} новых уведомлений` };
    // One email per recipient, while each item still uses its own configured template.
    const genericTemplate = templates.other ?? {};
    const subjectTemplate = str(genericTemplate.subject || '{account}, сводка уведомлений: {message}');
    const subject = fill(subjectTemplate, values).slice(0, 240);
    const body = `Здравствуйте, ${login}!\n\nЗа время вашего отсутствия накопились непрочитанные уведомления (${section}):\n\n${lines.join('\n\n')}\n\nОткройте Orhei A11, чтобы ознакомиться с ними.`;
    const { data: logRow } = await supabase.from('email_send_logs').insert({ recipient_login: login, recipient_email: claimed[0].email, email_type: 'digest', subject, body, status: 'attempt' }).select('id').maybeSingle();
    try {
      await transporter.sendMail({ from: `Orhei A11 <${gmailUser}>`, to: claimed[0].email, subject, text: body, html: `<div style="font-family:Arial,sans-serif;white-space:pre-wrap;line-height:1.6">${safe(body)}</div>` });
      if (logRow?.id) await supabase.from('email_send_logs').update({ status: 'sent' }).eq('id', logRow.id);
      sent++;
    } catch (e) {
      const message = e instanceof Error ? e.message : str(e);
      if (logRow?.id) await supabase.from('email_send_logs').update({ status: 'failed', error_message: message.slice(0, 2000) }).eq('id', logRow.id);
      // Roll back all claims in this digest so the next scheduled run can retry.
      for (const item of claimed) await supabase.from('email_notification_sent').delete().eq('notification_id', str(item.notification.id)).eq('recipient_login', login);
      errors++;
    }
  }
  return json({ ok: errors === 0, sent, skipped, errors, recipientsWithPending: pendingByLogin.size });
});
