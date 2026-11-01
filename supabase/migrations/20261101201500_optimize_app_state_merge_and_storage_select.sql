-- Permit owners to read back their own site-template objects. Supabase Storage
-- requires SELECT + UPDATE + INSERT when the client uploads with upsert=true.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'storage'
      AND tablename = 'objects'
      AND policyname = 'Site template assets readable by owners'
  ) THEN
    CREATE POLICY "Site template assets readable by owners"
      ON storage.objects
      FOR SELECT
      TO authenticated
      USING (
        bucket_id = 'site-assets'
        AND name LIKE 'templates/%'
        AND EXISTS (
          SELECT 1
          FROM public.profiles p
          WHERE p.id = auth.uid()
            AND lower(btrim(p.group_name)) = 'владельцы'
        )
      );
  END IF;
END
$$;

-- Replace the quadratic nested loops used for merging JSON arrays with set-based
-- joins. This preserves the original merge semantics while avoiding long locks
-- on public.app_state when large arrays (for example logs) are present.
CREATE OR REPLACE FUNCTION public._bomba_merge_jsonb(base_value jsonb, current_value jsonb, incoming_value jsonb)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
SECURITY INVOKER
SET search_path = ''
AS $function$
DECLARE
  result_value jsonb;
  key_name text;
BEGIN
  IF incoming_value IS NOT DISTINCT FROM base_value THEN
    RETURN current_value;
  END IF;

  IF jsonb_typeof(base_value) = 'object'
     AND jsonb_typeof(incoming_value) = 'object'
     AND jsonb_typeof(current_value) = 'object' THEN
    result_value := current_value;
    FOR key_name IN
      SELECT key FROM jsonb_object_keys(base_value || incoming_value) AS k(key)
    LOOP
      IF (incoming_value ? key_name) IS FALSE THEN
        IF (base_value ? key_name) AND result_value->key_name = base_value->key_name THEN
          result_value := result_value - key_name;
        END IF;
      ELSIF (base_value->key_name) IS DISTINCT FROM (incoming_value->key_name) THEN
        IF jsonb_typeof(base_value->key_name) = 'array'
           AND jsonb_typeof(incoming_value->key_name) = 'array'
           AND jsonb_typeof(result_value->key_name) = 'array' THEN
          result_value := jsonb_set(
            result_value,
            ARRAY[key_name],
            public._bomba_merge_jsonb(base_value->key_name, result_value->key_name, incoming_value->key_name),
            true
          );
        ELSE
          result_value := jsonb_set(result_value, ARRAY[key_name], incoming_value->key_name, true);
        END IF;
      END IF;
    END LOOP;
    RETURN result_value;
  END IF;

  IF jsonb_typeof(base_value) = 'array'
     AND jsonb_typeof(incoming_value) = 'array'
     AND jsonb_typeof(current_value) = 'array' THEN
    WITH base_items AS (
      SELECT value,
             CASE WHEN jsonb_typeof(value) = 'object' AND value ? 'id'
                  THEN 'id:' || (value->'id')::text
                  ELSE 'json:' || value::text END AS item_key
      FROM jsonb_array_elements(base_value) AS e(value)
    ),
    incoming_items AS (
      SELECT ord, value,
             CASE WHEN jsonb_typeof(value) = 'object' AND value ? 'id'
                  THEN 'id:' || (value->'id')::text
                  ELSE 'json:' || value::text END AS item_key
      FROM jsonb_array_elements(incoming_value) WITH ORDINALITY AS e(value, ord)
    ),
    current_items AS (
      SELECT ord, value,
             CASE WHEN jsonb_typeof(value) = 'object' AND value ? 'id'
                  THEN 'id:' || (value->'id')::text
                  ELSE 'json:' || value::text END AS item_key
      FROM jsonb_array_elements(current_value) WITH ORDINALITY AS e(value, ord)
    ),
    kept_current AS (
      SELECT c.ord,
             CASE
               WHEN b.item_key IS NOT NULL
                AND i.item_key IS NOT NULL
                AND i.value IS DISTINCT FROM b.value
               THEN i.value
               ELSE c.value
             END AS value,
             CASE
               WHEN b.item_key IS NOT NULL
                AND i.item_key IS NULL
                AND c.value = b.value
               THEN false
               ELSE true
             END AS keep_item
      FROM current_items c
      LEFT JOIN base_items b ON b.item_key = c.item_key
      LEFT JOIN incoming_items i ON i.item_key = c.item_key
    ),
    appended AS (
      SELECT (coalesce((SELECT max(ord) FROM current_items), 0) + i.ord) AS ord,
             i.value
      FROM incoming_items i
      LEFT JOIN base_items b ON b.item_key = i.item_key
      LEFT JOIN current_items c ON c.item_key = i.item_key
      WHERE (b.item_key IS NULL AND c.item_key IS NULL)
         OR (b.item_key IS NOT NULL AND c.item_key IS NULL AND i.value IS DISTINCT FROM b.value)
    )
    SELECT coalesce(jsonb_agg(value ORDER BY ord), '[]'::jsonb)
      INTO result_value
      FROM (
        SELECT ord, value FROM kept_current WHERE keep_item
        UNION ALL
        SELECT ord, value FROM appended
      ) merged_items;
    RETURN result_value;
  END IF;

  RETURN incoming_value;
END;
$function$;
