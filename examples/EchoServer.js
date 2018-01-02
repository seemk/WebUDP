const WebUDP = require("./WebUDP.node");
const express = require("express");
const cors = require("cors");
const dgram = require("dgram");

const HOST = "127.0.0.1";
const PORT = 9555;

/* An example how to use the WebUDP node addon. */
let app = express();
app.use(cors());
app.use(require("body-parser").text());

let udp = dgram.createSocket("udp4");
let host = new WebUDP.Host(HOST, PORT);

host.setUDPWriteFunction((msg, {port, address}) => {
  udp.send(msg, port, address);
});

host.onClientJoin(({clientId, address, port}) => {
  console.log(`client id=${clientId} ${address}:${port} joined`);
});

host.onClientLeave(({clientId}) => {
  console.log(`client id=${clientId} left`);
});

host.onTextData(({text, clientId, address, port}) => {
  console.log(`received text data from client ${clientId}: ${text}`);
  host.sendText(clientId, text);
});

app.post("/", (req, res) => {
  let sdp = host.exchangeSDP(req.body);
  if (!sdp) {
    res.status(400).end();
    return;
  }

  res.send(sdp); 
});

udp.on("message", (msg, addr) => {
  host.handleUDP(msg, addr);
});

app.listen(PORT);
udp.bind(PORT);

setInterval(() => {
  host.serve();
}, 10);
