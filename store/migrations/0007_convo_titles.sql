-- Backfill conversation titles: name each still-unnamed conversation after its
-- first user message (newlines/tabs collapsed to spaces, truncated). New
-- conversations are titled in the app; this fixes the pile of "New conversation"
-- rows created before auto-titling existed.
UPDATE conversations
SET title = (
    SELECT rtrim(substr(
        replace(replace(replace(trim(m.content), char(10), ' '), char(13), ' '), char(9), ' '),
        1, 48))
    FROM messages m
    WHERE m.conversation_id = conversations.id AND m.role = 'user'
    ORDER BY m.id LIMIT 1
)
WHERE (title = 'New conversation' OR title IS NULL OR title = '')
  AND EXISTS (
    SELECT 1 FROM messages m2
    WHERE m2.conversation_id = conversations.id AND m2.role = 'user'
  );
