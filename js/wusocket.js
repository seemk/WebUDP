var WuSocket = function(address) {
  this.address = address;
  this.channel = null;
  this.onmessage = null;
  this.onopen = null;
  this.beginConnection();
};

WuSocket.prototype.send = function(data) {
  this.channel.send(data);
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
      console.log("received ice candidate");
      console.log(evt);
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
    if (typeof(socket.onopen) == "function") {
      socket.onopen();
    }
  };

  channel.onclose = function() {
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
    $.ajax({
      "type": "POST",
      url: socket.address,
      data: peer.localDescription.sdp,
      success: function(response) {
        console.log(JSON.stringify(response));
        peer.setRemoteDescription(new RTCSessionDescription(response.answer)).then(function() {
          var candidate = new RTCIceCandidate(response.candidate);
          peer.addIceCandidate(candidate).then(function() {
            console.log("add ice candidate success");
          }).catch(function(err) {
            console.log("Error: Failure during addIceCandidate()", err);
          });
        })
        .catch(function(e) {
          console.log("set remote description fail");
          console.log(e);
        });
      },
      dataType: "json"
    });
  }).catch(function(reason) {
    console.log("create offer fail " + reason);
  });
};
