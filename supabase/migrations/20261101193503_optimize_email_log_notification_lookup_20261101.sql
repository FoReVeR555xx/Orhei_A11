-- Supports the batched notification-log lookup used by the optimized email worker.
create index if not exists email_send_logs_notification_login_status_idx
  on public.email_send_logs (notification_id, recipient_login, status)
  where notification_id is not null;
