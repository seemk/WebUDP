#include <arpa/inet.h>
#include <nan.h>
#include "WuHost.h"

const char* const kInvalidArgumentCountErr = "Wrong number of arguments";
const char* const kInvalidArguments = "Invalid arguments";

struct Address {
  Address(uint32_t addr, uint16_t port) : address(addr), port(port) {
    snprintf(textAddress, sizeof(textAddress), "%u.%u.%u.%u",
             (addr & 0xFF000000) >> 24, (addr & 0x00FF0000) >> 16,
             (addr & 0x0000FF00) >> 8, (addr & 0x000000FF));
  }

  uint32_t address;
  uint16_t port;
  char textAddress[16];
};

struct WuHost {
  Wu* wu = nullptr;
};

class WuHostWrap : public Nan::ObjectWrap {
 public:
  static NAN_MODULE_INIT(Init);

  explicit WuHostWrap(Wu* wu);
  ~WuHostWrap();

  static NAN_METHOD(New);
  static NAN_METHOD(ExchangeSDP);
  static NAN_METHOD(SetUDPWriteFunction);
  static NAN_METHOD(HandleUDP);
  static NAN_METHOD(Serve);
  static NAN_METHOD(SetClientJoinFunction);
  static NAN_METHOD(SetClientLeaveFunction);
  static NAN_METHOD(SetTextDataReceivedFunction);
  static NAN_METHOD(SetBinaryDataReceivedFunction);
  static NAN_METHOD(RemoveClient);
  static Nan::Persistent<v8::Function> constructor;

  uint64_t idCounter = 1;
  WuHost host;
  Nan::Callback udpWriteCallback;
  Nan::Callback clientJoinCallback;
  Nan::Callback clientLeaveCallback;
  Nan::Callback textDataCallback;
  Nan::Callback binaryDataCallback;

  void HandleClientJoin(WuClient* client);
  void HandleClientLeave(WuClient* client);
  void HandleContent(const WuEvent* evt);
};

void WuHostWrap::HandleClientJoin(WuClient* client) {
  uintptr_t id = (uintptr_t)WuClientGetUserData(client);

  if (!id) {
    id = idCounter++;
    WuClientSetUserData(client, (void*)id);
  }

  WuAddress address = WuClientGetAddress(client);
  Address remote(address.host, address.port);

  auto args = Nan::New<v8::Object>();
  Nan::Set(args, Nan::New("address").ToLocalChecked(),
           Nan::New(remote.textAddress).ToLocalChecked());
  Nan::Set(args, Nan::New("port").ToLocalChecked(), Nan::New(remote.port));
  Nan::Set(args, Nan::New("clientId").ToLocalChecked(), Nan::New((uint32_t)id));

  const int argc = 1;
  v8::Local<v8::Value> argv[argc] = {args};
  clientJoinCallback.Call(argc, argv);
}

void WuHostWrap::HandleClientLeave(WuClient* client) {
  uintptr_t id = (uintptr_t)WuClientGetUserData(client);
  WuAddress address = WuClientGetAddress(client);
  Address remote(address.host, address.port);

  auto args = Nan::New<v8::Object>();
  Nan::Set(args, Nan::New("address").ToLocalChecked(),
           Nan::New(remote.textAddress).ToLocalChecked());
  Nan::Set(args, Nan::New("port").ToLocalChecked(), Nan::New(remote.port));
  Nan::Set(args, Nan::New("clientId").ToLocalChecked(), Nan::New((uint32_t)id));

  const int argc = 1;
  v8::Local<v8::Value> argv[argc] = {args};
  clientLeaveCallback.Call(argc, argv);

  WuRemoveClient(host.wu, client);
}

void WuHostWrap::HandleContent(const WuEvent* evt) {
  uintptr_t id = (uintptr_t)WuClientGetUserData(evt->client);

  WuAddress address = WuClientGetAddress(evt->client);
  Address remote(address.host, address.port);

  auto args = Nan::New<v8::Object>();
  Nan::Set(args, Nan::New("address").ToLocalChecked(),
           Nan::New(remote.textAddress).ToLocalChecked());
  Nan::Set(args, Nan::New("port").ToLocalChecked(), Nan::New(remote.port));
  Nan::Set(args, Nan::New("clientId").ToLocalChecked(), Nan::New((uint32_t)id));

  const int argc = 1;

  if (evt->type == WuEvent_TextData) {
    Nan::Set(args, Nan::New("text").ToLocalChecked(),
             Nan::New((const char*)evt->data, evt->length).ToLocalChecked());
    v8::Local<v8::Value> argv[argc] = {args};
    textDataCallback.Call(argc, argv);
  } else if (evt->type == WuEvent_BinaryData) {
    auto buf = Nan::CopyBuffer((const char*)evt->data, (uint32_t)evt->length)
                   .ToLocalChecked();
    Nan::Set(args, Nan::New("data").ToLocalChecked(), buf);
    v8::Local<v8::Value> argv[argc] = {args};
    binaryDataCallback.Call(argc, argv);
  }
}

void WriteUDPData(const uint8_t* data, size_t length, const WuClient* client,
                  void* userData) {
  WuHostWrap* wrap = (WuHostWrap*)userData;

  WuAddress address = WuClientGetAddress(client);

  Address remote(address.host, address.port);

  auto buf =
      Nan::CopyBuffer((const char*)data, (uint32_t)length).ToLocalChecked();

  auto addr = Nan::New<v8::Object>();
  Nan::Set(addr, Nan::New("address").ToLocalChecked(),
           Nan::New(remote.textAddress).ToLocalChecked());
  Nan::Set(addr, Nan::New("port").ToLocalChecked(), Nan::New(remote.port));

  const int argc = 2;
  v8::Local<v8::Value> argv[argc] = {buf, addr};
  wrap->udpWriteCallback.Call(argc, argv);
}

Nan::Persistent<v8::Function> WuHostWrap::constructor;

NAN_MODULE_INIT(WuHostWrap::Init) {
  v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
  tpl->SetClassName(Nan::New("Host").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "exchangeSDP", ExchangeSDP);
  Nan::SetPrototypeMethod(tpl, "setUDPWriteFunction", SetUDPWriteFunction);
  Nan::SetPrototypeMethod(tpl, "handleUDP", HandleUDP);
  Nan::SetPrototypeMethod(tpl, "serve", Serve);
  Nan::SetPrototypeMethod(tpl, "onClientJoin", SetClientJoinFunction);
  Nan::SetPrototypeMethod(tpl, "onClientLeave", SetClientLeaveFunction);
  Nan::SetPrototypeMethod(tpl, "onTextData", SetTextDataReceivedFunction);
  Nan::SetPrototypeMethod(tpl, "onBinaryData", SetBinaryDataReceivedFunction);

  constructor.Reset(tpl->GetFunction());
  Nan::Set(target, Nan::New("Host").ToLocalChecked(),
           Nan::GetFunction(tpl).ToLocalChecked());
}

WuHostWrap::WuHostWrap(Wu* wu) { host.wu = wu; }
WuHostWrap::~WuHostWrap() { free(host.wu); }

NAN_METHOD(WuHostWrap::New) {
  if (info.Length() < 2) {
    Nan::ThrowError(kInvalidArgumentCountErr);
    return;
  }

  if (info.IsConstructCall()) {
    std::string host =
        *v8::String::Utf8Value(Nan::To<v8::String>(info[0]).ToLocalChecked());
    std::string port =
        *v8::String::Utf8Value(Nan::To<v8::String>(info[1]).ToLocalChecked());

    WuConf conf;
    conf.host = host.c_str();
    conf.port = port.c_str();

    Wu* wu = (Wu*)calloc(1, sizeof(Wu));
    if (!WuInit(wu, &conf)) {
      Nan::ThrowError("Initialization error");
      return;
    }

    WuHostWrap* obj = new WuHostWrap(wu);
    WuSetUserData(wu, obj);
    WuSetUDPWriteFunction(wu, WriteUDPData);

    obj->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  } else {
    const int argc = 2;
    v8::Local<v8::Value> argv[argc] = {info[0], info[1]};
    v8::Local<v8::Function> cons = Nan::New(constructor);
    info.GetReturnValue().Set(
        Nan::NewInstance(cons, argc, argv).ToLocalChecked());
  }
}

NAN_METHOD(WuHostWrap::ExchangeSDP) {
  if (info.Length() < 1) {
    Nan::ThrowError(kInvalidArgumentCountErr);
    return;
  }

  WuHostWrap* obj = Nan::ObjectWrap::Unwrap<WuHostWrap>(info.This());
  Wu* wu = obj->host.wu;

  std::string sdp =
      *v8::String::Utf8Value(Nan::To<v8::String>(info[0]).ToLocalChecked());

  const SDPResult res = WuExchangeSDP(wu, sdp.c_str(), sdp.size());

  if (res.status == WuSDPStatus_Success) {
    Nan::MaybeLocal<v8::String> responseSdp =
        Nan::New<v8::String>(res.sdp, res.sdpLength);
    info.GetReturnValue().Set(responseSdp.ToLocalChecked());
    return;
  }

  info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(WuHostWrap::SetUDPWriteFunction) {
  if (info.Length() < 1 || !info[0]->IsFunction()) {
    Nan::ThrowError(kInvalidArguments);
    return;
  }

  WuHostWrap* obj = Nan::ObjectWrap::Unwrap<WuHostWrap>(info.This());
  obj->udpWriteCallback.Reset(Nan::To<v8::Function>(info[0]).ToLocalChecked());
}

NAN_METHOD(WuHostWrap::HandleUDP) {
  if (info.Length() < 2) {
    Nan::ThrowError(kInvalidArgumentCountErr);
    return;
  }

  WuHostWrap* obj = Nan::ObjectWrap::Unwrap<WuHostWrap>(info.This());
  Wu* wu = obj->host.wu;

  auto buf = info[0]->ToObject();
  char* data = node::Buffer::Data(buf);
  size_t length = node::Buffer::Length(buf);

  auto ipObj = info[1]->ToObject();
  v8::String::Utf8Value ipVal(
      Nan::Get(ipObj, Nan::New("address").ToLocalChecked()).ToLocalChecked());

  struct in_addr address;
  inet_pton(AF_INET, *ipVal, &address);
  uint32_t ip = ntohl(address.s_addr);
  uint32_t port = Nan::Get(ipObj, Nan::New("port").ToLocalChecked())
                      .ToLocalChecked()
                      ->Uint32Value();

  WuAddress remote;
  remote.host = ip;
  remote.port = port;

  WuHandleUDP(wu, &remote, (const uint8_t*)data, length);
}

NAN_METHOD(WuHostWrap::Serve) {
  WuHostWrap* obj = Nan::ObjectWrap::Unwrap<WuHostWrap>(info.This());
  Wu* wu = obj->host.wu;

  WuEvent evt;
  while (WuUpdate(wu, &evt)) {
    switch (evt.type) {
      case WuEvent_ClientJoin: {
        obj->HandleClientJoin(evt.client);
        break;
      }
      case WuEvent_TextData:
      case WuEvent_BinaryData: {
        obj->HandleContent(&evt);
        break;
      }
      case WuEvent_ClientLeave: {
        obj->HandleClientLeave(evt.client);
      }
      default:
        break;
    }
  }
}

NAN_METHOD(WuHostWrap::SetClientJoinFunction) {
  if (info.Length() < 1 || !info[0]->IsFunction()) {
    Nan::ThrowError(kInvalidArguments);
    return;
  }

  WuHostWrap* obj = Nan::ObjectWrap::Unwrap<WuHostWrap>(info.This());
  obj->clientJoinCallback.Reset(
      Nan::To<v8::Function>(info[0]).ToLocalChecked());
}

NAN_METHOD(WuHostWrap::SetClientLeaveFunction) {
  if (info.Length() < 1 || !info[0]->IsFunction()) {
    Nan::ThrowError(kInvalidArguments);
    return;
  }

  WuHostWrap* obj = Nan::ObjectWrap::Unwrap<WuHostWrap>(info.This());
  obj->clientLeaveCallback.Reset(
      Nan::To<v8::Function>(info[0]).ToLocalChecked());
}

NAN_METHOD(WuHostWrap::SetBinaryDataReceivedFunction) {
  if (info.Length() < 1 || !info[0]->IsFunction()) {
    Nan::ThrowError(kInvalidArguments);
    return;
  }

  WuHostWrap* obj = Nan::ObjectWrap::Unwrap<WuHostWrap>(info.This());
  obj->binaryDataCallback.Reset(
      Nan::To<v8::Function>(info[0]).ToLocalChecked());
}

NAN_METHOD(WuHostWrap::SetTextDataReceivedFunction) {
  if (info.Length() < 1 || !info[0]->IsFunction()) {
    Nan::ThrowError(kInvalidArguments);
    return;
  }

  WuHostWrap* obj = Nan::ObjectWrap::Unwrap<WuHostWrap>(info.This());
  obj->textDataCallback.Reset(Nan::To<v8::Function>(info[0]).ToLocalChecked());
}

NAN_MODULE_INIT(Init) { WuHostWrap::Init(target); }
NODE_MODULE(WebUDP, Init);
