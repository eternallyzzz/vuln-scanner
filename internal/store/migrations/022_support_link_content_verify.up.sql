-- HEAD-based verification is not trustworthy: support.microsoft.com returns
-- HTTP 200 for unrelated fallback articles. Reset every previously "ok"
-- status so the content-level checker (title/body contains the KB number)
-- revalidates them once on the next server start.
UPDATE kb_metadata SET status='unknown', verified_at=NULL WHERE status='ok';
