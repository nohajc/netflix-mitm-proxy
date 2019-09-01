# netflix-mitm-proxy

This is a mitmproxy script which will decrypt Netflix MSL requests and responses

## How to use

1. Install mitmproxy: https://docs.mitmproxy.org/stable/overview-installation/
2. Install HTTPS certificate: https://docs.mitmproxy.org/stable/concepts-certificates/
3. Configure your browser or system to use localhost:8080 as HTTP and HTTPS proxy
4. Run `mitmdump -s msl_decrypt.py` (8080 is the default port, can be changed with `-p` option)
5. Analyze the generated `proxy.log`
6. Profit
