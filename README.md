# Autopush Interceptor

PROOF OF CONCEPT STAGE

This is a simple server that emulates the Mozilla autopush server, POC for running your custom push service for web-push capable web applications. (WIP)

## Progress

- Websocket Side
  - [X] Hello
  - [X] Register
  - [ ] Unregister
  - [ ] Relay official broadcasts
- Ingestion Side
  - [X] Decode and verify VAPID
  - [X] Decode ECDH
  - [ ] E2E MITM

## Usage

```bash
cargo run -- --public-url https://example.com
```

Set `dom.push.serverURL` to `wss://example.com` (If using `ws://` you need to set `dom.push.testing.allowInsecureServerURL` to `true`)

## References

- [Official autopush code](https://github.com/mozilla-services/autopush-rs)
- [Push JS API](https://developer.mozilla.org/en-US/docs/Web/API/Push_API)
- [Autopush Client Internals](https://firefox-source-docs.mozilla.org/dom/push/index.html)
- [Autopush Architecture](https://firefox-source-docs.mozilla.org/dom/push/index.html)
- [Autopush Browser Debugging Tips](https://autopush.readthedocs.io/en/latest/testing.html)

## License

Apache 2.0
