# light-stash-client-py

python client implementation for `light-stash` database https://github.com/A7fa7fa/light-stash

No prod ready code. I use this for testing purpose

## How to

```python
with LightStashConnectionPool(
    host="localhost",
    port=1234,
    max_connections=1,
    idle_timeout=300,
    use_tls=True,
    cafile="../certs/cert.pem",
    sock_timeout=300,
) as pool:
    with pool.connection() as conn:
        conn.ping()

        value = "some-value"
        key = "some-key"
        conn.set(key, value)
        resp_value = conn.get(key)
```

TODO:
- proper response object
- unit testing
- byte buffer
- async with connection pooling
- pipeling multiple requests
- error handling
- logging
