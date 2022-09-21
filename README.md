# Socks5 Proxy Proxy

This crate is a **very** simple local Socks5 proxy, that proxies to a remote Socks5 proxy, adding authentication.
This is done as a simple trampoline so that tools (FireFox, `nc` on macOS, etc.) that don't support Socks5 authentication schemes can be made to work with remote Socks5 proxies that do.

## Running

```
s5pp -p $REMOTE_PROXY_ADDRESS -a $USERNAME:$PASSWORD
```
