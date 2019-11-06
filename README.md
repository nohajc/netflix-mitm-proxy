# netflix-mitm-proxy

This is a mitmproxy script which will decrypt Netflix MSL requests and responses

## How to use

1. Install mitmproxy: https://docs.mitmproxy.org/stable/overview-installation/
2. Install HTTPS certificate: https://docs.mitmproxy.org/stable/concepts-certificates/
3. Configure your browser or system to use localhost:8080 as HTTP and HTTPS proxy
4. Run `mitmdump -s msl_decrypt.py` (8080 is the default port, can be changed with `-p` option)
5. Analyze the generated `proxy.log`
6. Profit

## Gotchas

For the decryption to work, mitmproxy has to intercept MSL handshake.
That usually happens only after the very first login to Netflix
or when a previous session has expired.

To force new handshake, either clear all cookies and local storage for all Netflix domains
or just create a new browser profile which will have empty history.

After the script is first run, it will save the negotiated AES key
to current working directory and use it next time.
