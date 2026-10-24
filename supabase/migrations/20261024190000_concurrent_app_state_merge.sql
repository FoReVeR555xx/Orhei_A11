create or replace function public._bomba_same_json_item(a jsonb, b jsonb)
returns boolean
language sql
immutable
security invoker
set search_path = ''
as $$
  select case
    when jsonb_typeof(a) = 'object' and jsonb_typeof(b) = 'object'
      and a ? 'id' and b ? 'id'
      then a->'id' = b->'id'
    else a = b
  end;
$$;

create or replace function public._bomba_merge_jsonb(base_value jsonb, current_value jsonb, incoming_value jsonb)
returns jsonb
language plpgsql
immutable
security invoker
set search_path = ''
as $$
declare
  result_value jsonb;
  key_name text;
  base_item jsonb;
  incoming_item jsonb;
  current_item jsonb;
  found boolean;
  i integer;
begin
  if incoming_value is not distinct from base_value then
    return current_value;
  end if;

  if jsonb_typeof(base_value) = 'object'
     and jsonb_typeof(incoming_value) = 'object'
     and jsonb_typeof(current_value) = 'object' then
    result_value := current_value;
    for key_name in select key from jsonb_object_keys(base_value || incoming_value) as k(key)
    loop
      if (incoming_value ? key_name) is false then
        if (base_value ? key_name) and result_value->key_name = base_value->key_name then
          result_value := result_value - key_name;
        end if;
      elsif (base_value->key_name) is distinct from (incoming_value->key_name) then
        if jsonb_typeof(base_value->key_name) = 'array'
           and jsonb_typeof(incoming_value->key_name) = 'array'
           and jsonb_typeof(result_value->key_name) = 'array' then
          result_value := jsonb_set(result_value, array[key_name], public._bomba_merge_jsonb(base_value->key_name, result_value->key_name, incoming_value->key_name), true);
        else
          result_value := jsonb_set(result_value, array[key_name], incoming_value->key_name, true);
        end if;
      end if;
    end loop;
    return result_value;
  end if;

  if jsonb_typeof(base_value) = 'array'
     and jsonb_typeof(incoming_value) = 'array'
     and jsonb_typeof(current_value) = 'array' then
    result_value := current_value;
    -- Remove only entries that this client actually removed, and only when the
    -- server still has the unchanged base version of that entry.
    for base_item in select value from jsonb_array_elements(base_value) as e(value)
    loop
      found := false;
      for incoming_item in select value from jsonb_array_elements(incoming_value) as e(value)
      loop
        if public._bomba_same_json_item(base_item, incoming_item) then found := true; exit; end if;
      end loop;
      if not found then
        for i in reverse (jsonb_array_length(result_value)-1)..0 loop
          current_item := result_value->i;
          if public._bomba_same_json_item(base_item, current_item) then
            if current_item = base_item then
              result_value := result_value - i;
            end if;
            exit;
          end if;
        end loop;
      end if;
    end loop;
    -- Apply edits/new entries from this client while preserving additions by others.
    for incoming_item in select value from jsonb_array_elements(incoming_value) as e(value)
    loop
      base_item := null;
      for current_item in select value from jsonb_array_elements(base_value) as e(value)
      loop
        if public._bomba_same_json_item(incoming_item, current_item) then base_item := current_item; exit; end if;
      end loop;
      if base_item is null then
        found := false;
        for current_item in select value from jsonb_array_elements(result_value) as e(value)
        loop
          if public._bomba_same_json_item(incoming_item, current_item) then found := true; exit; end if;
        end loop;
        if not found then result_value := result_value || jsonb_build_array(incoming_item); end if;
      elsif incoming_item is distinct from base_item then
        found := false;
        for i in 0..(jsonb_array_length(result_value)-1) loop
          current_item := result_value->i;
          if public._bomba_same_json_item(incoming_item, current_item) then
            result_value := jsonb_set(result_value, array[i::text], incoming_item, false);
            found := true;
            exit;
          end if;
        end loop;
        if not found then result_value := result_value || jsonb_build_array(incoming_item); end if;
      end if;
    end loop;
    return result_value;
  end if;

  return incoming_value;
end;
$$;

create or replace function public.merge_app_state(p_base jsonb, p_incoming jsonb)
returns jsonb
language plpgsql
security invoker
set search_path = ''
as $$
declare
  current_payload jsonb;
  merged_payload jsonb;
begin
  if auth.uid() is null then
    raise exception 'Authentication required';
  end if;
  select payload into current_payload from public.app_state where id = 'main' for update;
  if not found then
    insert into public.app_state(id, payload, updated_at, updated_by)
    values ('main', coalesce(p_incoming, '{}'::jsonb), now(), auth.uid())
    on conflict (id) do nothing;
    select payload into current_payload from public.app_state where id = 'main' for update;
  end if;
  merged_payload := public._bomba_merge_jsonb(coalesce(p_base, '{}'::jsonb), coalesce(current_payload, '{}'::jsonb), coalesce(p_incoming, '{}'::jsonb));
  update public.app_state
     set payload = merged_payload, updated_at = now(), updated_by = auth.uid()
   where id = 'main';
  return merged_payload;
end;
$$;

revoke execute on function public._bomba_same_json_item(jsonb, jsonb) from public, anon;
revoke execute on function public._bomba_merge_jsonb(jsonb, jsonb, jsonb) from public, anon;
revoke execute on function public.merge_app_state(jsonb, jsonb) from public, anon;
grant execute on function public._bomba_same_json_item(jsonb, jsonb) to authenticated;
grant execute on function public._bomba_merge_jsonb(jsonb, jsonb, jsonb) to authenticated;
grant execute on function public.merge_app_state(jsonb, jsonb) to authenticated;
