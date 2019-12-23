# netflix-mitm-proxy

This is a mitmproxy script which will decrypt Netflix MSL requests and responses

## How to use

1. Install mitmproxy: https://docs.mitmproxy.org/stable/overview-installation/
2. Install HTTPS certificate: https://docs.mitmproxy.org/stable/concepts-certificates/
3. Configure your browser or system to use localhost:8080 as HTTP and HTTPS proxy
4. Run `mitmdump -s msl_decrypt.py` (8080 is the default port, can be changed with `-p` option)
5. Analyze the generated `proxy.log`
6. Profit

### How to use on Windows

1. Install Python 3
2. On shell run:<br/>
pip install mitmproxy<br/>
pip install pycryptodomex
3. Install HTTPS certificate as described in the mitmproxy guide

#### How run on Windows 10

1. Run `mitmdump -s msl_decrypt.py` (8080 is the default port, can be changed with `-p` option)
2. Open settings, and click Network & Internet, so click Proxy
3. In the Manual Proxy Setup section, set the `Use a Proxy Server` switch to On
4. In the Address field 127.0.0.1, in the Port field the choosen proxy port (default 8080)
5. Press Save, after about ten seconds mitmproxy will begin to receive

## Troubleshooting

### mitmproxy on Windows cannot find python dependencies

Don't use the mitmproxy Windows installer because it includes a bundled python runtime which won't see any libraries installed with pip.

Installing mitmproxy with pip should work. Alternatively, the Linux version can be used in [WSL](https://docs.microsoft.com/en-us/windows/wsl/install-win10).

### Decryption doesn't work

For the decryption to work, mitmproxy has to intercept MSL handshake.
That usually happens only after the very first login to Netflix
or when a previous session has expired.

To force new handshake, either clear all cookies and local storage for all Netflix domains
or just create a new browser profile which will have empty history.

After the script is first run, it will save the negotiated AES key
to current working directory and use it next time.
