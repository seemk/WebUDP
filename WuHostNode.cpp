#include <nan.h>
#include "WuHost.h"

const char* const kInvalidArgumentCountErr = "Wrong number of arguments";

struct WuHost {
  Wu* wu = nullptr;
};

class WuHostWrap : public Nan::ObjectWrap {
 public:
  static NAN_MODULE_INIT(Init);

 private:
  explicit WuHostWrap(Wu* wu);
  ~WuHostWrap();

  static NAN_METHOD(New);
  static NAN_METHOD(ExchangeSDP);
  static Nan::Persistent<v8::Function> constructor;

  WuHost host;
};

Nan::Persistent<v8::Function> WuHostWrap::constructor;

NAN_MODULE_INIT(WuHostWrap::Init) {
  v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
  tpl->SetClassName(Nan::New("Host").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);

  Nan::SetPrototypeMethod(tpl, "exchangeSDP", ExchangeSDP);

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

  std::string sdp = *v8::String::Utf8Value(Nan::To<v8::String>(info[0]).ToLocalChecked());

  const SDPResult res = WuExchangeSDP(wu, sdp.c_str(), sdp.size());

  if (res.status == WuSDPStatus_Success) {
    Nan::MaybeLocal<v8::String> responseSdp = Nan::New<v8::String>(res.sdp, res.sdpLength);
    info.GetReturnValue().Set(responseSdp.ToLocalChecked());
    return;
  }

  info.GetReturnValue().Set(Nan::Null());
}

NAN_MODULE_INIT(Init) { WuHostWrap::Init(target); }
NODE_MODULE(WebUDP, Init);
