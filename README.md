# WebUDP
Minimal WebRTC datachannel server

[Echo server demo](https://www.vektor.space/webudprtt.html) (Chrome, Firefox and maybe Safari 11)

The library implements a minimal subset of WebRTC (grossly violating specs) to achieve unreliable and out of order UDP transfer for browser clients.

Only Linux is supported at the moment.

### Issues
* Firefox doesn't connect to a server running on localhost. Bind a different interface.
