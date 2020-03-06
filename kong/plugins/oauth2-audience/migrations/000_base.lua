return {
  postgres = {
    up = [[
        CREATE TABLE IF NOT EXISTS "oauth2_audiences" (
          "id"           UUID                         PRIMARY KEY,
          "created_at"   TIMESTAMP WITH TIME ZONE     DEFAULT (CURRENT_TIMESTAMP(0) AT TIME ZONE 'UTC'),
          "consumer_id"  UUID                         REFERENCES "consumers" ("id") ON DELETE CASCADE,
          "audience"     TEXT                         UNIQUE,
          "issuer"       TEXT,
          "client_id"    TEXT,
          "tags"         TEXT[],
          "ttl"          TIMESTAMP WITH TIME ZONE
        );

        DO $$
        BEGIN
          CREATE INDEX IF NOT EXISTS "oauth2_audience_consumer_id_idx"
            ON "oauth2_audiences" ("consumer_id");
        EXCEPTION WHEN UNDEFINED_COLUMN THEN
          -- Do nothing, accept existing state
        END$$;

        DO $$
        BEGIN
          CREATE INDEX IF NOT EXISTS "oauth2_audience_tags_idx" ON "oauth2_audiences" USING GIN(tags);
        EXCEPTION WHEN UNDEFINED_COLUMN THEN
          -- Do nothing, accept existing state
        END$$;

        DO $$
        BEGIN
          CREATE TRIGGER "oauth2_audience_sync_tags_trigger"
            AFTER INSERT OR UPDATE OF tags OR DELETE ON "oauth2_audiences"
            FOR EACH ROW
            EXECUTE PROCEDURE sync_tags();
        EXCEPTION WHEN UNDEFINED_COLUMN OR UNDEFINED_TABLE THEN
          -- Do nothing, accept existing state
        END$$;

        DO $$
        BEGIN
          CREATE INDEX IF NOT EXISTS "oauth2_audience_ttl_idx" ON "oauth2_audiences" (ttl);
        EXCEPTION WHEN UNDEFINED_TABLE THEN
          -- Do nothing, accept existing state
        END$$;
      ]]
  },
  cassandra = {
    up = [[
        CREATE TABLE IF NOT EXISTS oauth2_audiences(
          id          uuid PRIMARY KEY,
          created_at  timestamp,
          consumer_id uuid,
          audience    text,
          issuer      text,
          client_id   text,
          tags        set<text>
        );
        CREATE INDEX IF NOT EXISTS ON oauth2_audiences(audience);
        CREATE INDEX IF NOT EXISTS ON oauth2_audiences(consumer_id);
      ]]
  }
}
