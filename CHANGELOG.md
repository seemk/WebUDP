## 0.3.0 (16.07.2018)
- Fix potential out of bounds read when sending SDP response.

## 0.2.0 (12.01.2018)
- Add DTLS 1.2 support. Requires at least OpenSSL 1.0.2.

## 0.1.1 (01.01.2018)
- Fix WuConf uninitialized maxClients parameter.

## 0.1.0 (30.12.2017)
- Remove the old default epoll implementation.
- Split the core logic into a separate library.
- Add a new epoll host.
- Add a Node.js host.
- Add fuzz tests.
- Add a Node.js example.
