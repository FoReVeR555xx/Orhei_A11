import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import nodemailer from 'npm:nodemailer@6.9.16';

const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type' };
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { ...cors, 'Content-Type': 'application/json' } });
const str = (v: unknown) => String(v ?? '');
const safe = (v: string) => v.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
function fill(template: string, values: Record<string,string>) { return template.replace(/\{(account|section|message)\}/g, (_, k) => values[k] ?? ''); }
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
  if (!emailCfg.enabled) return json({ ok: true, sent: 0, skipped: 'disabled' });
  const delayMs = Math.max(1, Math.min(10080, Number(emailCfg.delayMinutes) || 60)) * 60000;
  const recipients: Record<string,string> = emailCfg.recipients ?? {};
  const templates = emailCfg.templates ?? {};
  const transporter = nodemailer.createTransport({ host: 'smtp.gmail.com', port: 465, secure: true, auth: { user: gmailUser, pass: gmailPass } });
  const announcements = Array.isArray(payload.announcements) ? payload.announcements : [];
  let sent = 0, skipped = 0, errors = 0;
  for (const n of announcements) {
    const created = Number(n.createdAt) || Date.parse(n.createdAt || '') || 0;
    if (!n?.id || !created || Date.now() - created < delayMs) continue;
    const logins = [...new Set((Array.isArray(n.recipients) ? n.recipients : []).map((x: unknown) => str(x).trim().toLowerCase()).filter(Boolean))];
    for (const login of logins) {
      const email = str(recipients[login]).trim();
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { skipped++; continue; }
      const readBy = Array.isArray(n.readBy) ? n.readBy.map((x: unknown) => str(x).toLowerCase()) : [];
      if (readBy.includes(login)) { skipped++; continue; }
      const { data: prior, error: lookupError } = await supabase.from('email_notification_sent').select('notification_id').eq('notification_id', str(n.id)).eq('recipient_login', login).maybeSingle();
      if (lookupError) { errors++; continue; }
      if (prior) { skipped++; continue; }
      const kind = n.orderNotification ? 'productOrder' : (n.serviceActId || str(n.id).startsWith('ann-sa-')) ? 'serviceAct' : 'other';
      const section = kind === 'productOrder' ? 'Заказ товара' : kind === 'serviceAct' ? 'Сервис-Акт' : 'Уведомления';
      const t = templates[kind] ?? {};
      const values = { account: login, section, message: str(n.message) };
      const subject = fill(str(t.subject || (kind === 'productOrder' ? '{account}, у вас есть ответ во вкладке «Заказ товара»' : kind === 'serviceAct' ? '{account}, вам выдали сервис-акт' : '{account}, у вас новое уведомление')), values).slice(0, 240);
      const body = fill(str(t.body || 'Здравствуйте, {account}!\n\nУ вас есть непрочитанное уведомление в разделе «{section}».\n\n{message}'), values);
      // Claim this notification/recipient before sending, so concurrent cron runs cannot duplicate it.
      const { error: claimError } = await supabase.from('email_notification_sent').insert({ notification_id: str(n.id), recipient_login: login, recipient_email: email });
      if (claimError) { skipped++; continue; }
      try {
        await transporter.sendMail({ from: `Orhei A11 <${gmailUser}>`, to: email, subject, text: body, html: `<div style="font-family:Arial,sans-serif;white-space:pre-wrap;line-height:1.6">${safe(body)}</div>` });
        sent++;
      } catch (_e) {
        // Failed SMTP attempt is removed from the ledger, allowing a later retry.
        await supabase.from('email_notification_sent').delete().eq('notification_id', str(n.id)).eq('recipient_login', login);
        errors++;
      }
    }
  }
  return json({ ok: errors === 0, sent, skipped, errors });
});
