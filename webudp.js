const WebUDP = require("./build/Release/WebUDP.node");
const express = require("express");
const cors = require("cors");

const HOST = "localhost";
const PORT = 9555;

let app = express();
app.use(cors());
app.use(require("body-parser").text());

let host = new WebUDP.Host(HOST, PORT);

app.post("/", (req, res) => {
  let sdp = host.exchangeSDP(req.body);
  if (!sdp) {
    res.status(400).end();
    return;
  }

  res.send(sdp); 
});

app.listen(PORT);
