-- Repair the verified TN10 activity-feed gap without forcing another full
-- activity-feed rebuild. The refresh logic replays these txids directly.

INSERT INTO kcc20_projection_dirty (reason, txid, created_at_ms)
VALUES
    (
        'activity_feed_missing_trade_txid_backfill_20260809',
        decode('a390bae022d43effe2116468804c93d6215db8dbdac00b79c79c0dc055dfa44a', 'hex'),
        EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
    ),
    (
        'activity_feed_missing_trade_txid_backfill_20260809',
        decode('c3eaa3b8abfc6dee3ac0a7106c62ffee046611f4d483a38877a21e3eb98e51f6', 'hex'),
        EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
    ),
    (
        'activity_feed_missing_trade_txid_backfill_20260809',
        decode('a179b972576759140370283d0fef3cc07c7f20fd367b3f3979f144c8a1af1139', 'hex'),
        EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
    ),
    (
        'activity_feed_missing_trade_txid_backfill_20260809',
        decode('b174a6f02761aa10ca32294e977bf15930dd5c14a807b502ea1727bb32883820', 'hex'),
        EXTRACT(EPOCH FROM NOW())::BIGINT * 1000
    );
