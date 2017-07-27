var WuSocket = function(address) {
  this.address = address;
  this.channel = null;
  this.onmessage = null;
  this.onopen = null;
  this.open = false;
  this.beginConnection();
};

WuSocket.prototype.send = function(data) {
  if (this.open) {
    this.channel.send(data);
  } else {
    console.log("attempt to send in closed state");
  }
};

WuSocket.prototype.close = function() {
  this.channel.close();
};

WuSocket.prototype.beginConnection = function() {
  var socket = this;
  this.peer = new RTCPeerConnection({
    iceServers: [{
      urls: ["stun:stun.l.google.com:19302"]
    }]
  });
  var peer = this.peer;

  this.peer.onicecandidate = function(evt) {
    if (evt.candidate) {
      console.log("received ice candidate", evt.candidate);
    } else {
      console.log("all local candidates received");
    }
  };

  this.peer.ondatachannel = function(evt) {
    console.log("peer connection on data channel");
    console.log(evt);

  };

  this.channel = peer.createDataChannel("webudp", {
    ordered: false,
    maxRetransmits: 0
  });
  this.channel.binaryType = "arraybuffer";

  var channel = this.channel;

  channel.onopen = function() {
    console.log("data channel ready");
    socket.open = true;
    if (typeof(socket.onopen) == "function") {
      socket.onopen();
    }
  };

  channel.onclose = function() {
    this.open = false;
    console.log("data channel closed");
  };

  channel.onerror = function(evt) {
    console.log("data channel error " + evt.message);
  };

  channel.onmessage = function(evt) {
    if (typeof(socket.onmessage) == "function") {
      socket.onmessage(evt);
    }
  };

  peer.createOffer().then(function(offer) {
    return peer.setLocalDescription(offer);
  }).then(function() {
    let request = new XMLHttpRequest();
    request.open("POST", socket.address);
    request.onload = function() {
      if (request.status == 200) {
        let response = JSON.parse(request.responseText);
        peer.setRemoteDescription(new RTCSessionDescription(response.answer)).then(function() {
          let candidate = new RTCIceCandidate(response.candidate);
          peer.addIceCandidate(candidate).then(function() {
            console.log("add ice candidate success");
          }).catch(function(err) {
            console.log("Error: Failure during addIceCandidate()", err);
          });
        })
        .catch(function(e) {
          console.log("set remote description fail", e);
        });
      }
    };
    request.send(peer.localDescription.sdp);
  }).catch(function(reason) {
    console.log("create offer fail " + reason);
  });
};
