from src.lightstash_pool import LightStashConnectionPool

with LightStashConnectionPool(
    host="localhost",
    port=1234,
    max_connections=1,
    idle_timeout=300,
    use_tls=True,
    cafile="../light-stash/certs/cert.pem",
    sock_timeout=300,
) as pool:
    with pool.connection() as conn:
        conn.ping()

        value = "some-value"
        key = "some-key"
        conn.set(key, value)
        resp_value = conn.get(key)
        assert resp_value == value
        assert conn.delete(key) is True
        assert conn.delete(key + "asd") is False
        assert conn.get(key) is None
        conn.info()

        conn.set(key, value)
        assert conn.ttl(key) is None
        conn.set(key, value, 12345)
        assert conn.ttl(key) is not None

        assert conn.delete(key) is True

        conn.set(key, value)
        assert conn.ttl(key) is None
        conn.expire(key, 1234567)
