#include <nan.h>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "crypto/equihash.h"

#include <vector>

using namespace node;
using namespace v8;

const char* ToCString(const String::Utf8Value& value) {
  return *value ? *value : "<string conversion failed>";
}

int verifyEH(const char *hdr, const std::vector<unsigned char> &soln, const char *personalizationString, unsigned int N, unsigned int K) {
  // Hash state
  crypto_generichash_blake2b_state state;
  EhInitialiseState(N, K, state, personalizationString);

  crypto_generichash_blake2b_update(&state, (const unsigned char*)hdr, 140);

  bool isValid;
  EhIsValidSolution(N, K, state, soln, isValid);

  return isValid;
}

void verify(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();

  if (args.Length() < 4) {
    do {
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    } while (0);
  }

  if (!args[3]->IsInt32() || !args[4]->IsInt32()) {
    do {
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Fouth and fifth parameters should be equihash parameters (n, k)")));
        return;
    } while (0);
  }

  if (!args[2]->IsString()) {
    do {
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Third argument should be the personalization string.")));
        return;
    } while (0);
  }

  Local<Object> header = args[0]->ToObject(isolate);
  Local<Object> solution = args[1]->ToObject(isolate);

  if(!Buffer::HasInstance(header) || !Buffer::HasInstance(solution)) {
    do {
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "First two arguments should be buffer objects.")));
        return;
    } while (0);
  }

  const char *hdr = Buffer::Data(header);
  if(Buffer::Length(header) != 140) {
    //invalid hdr length
    args.GetReturnValue().Set(Boolean::New(isolate, false));
    return;
  }

  const char *soln = Buffer::Data(solution);

  std::vector<unsigned char> vecSolution(soln, soln + Buffer::Length(solution));

  String::Utf8Value personalizationString(isolate, args[2]);

  Local<Context> currentContext = isolate->GetCurrentContext();

  bool result = verifyEH(hdr, vecSolution, ToCString(personalizationString), args[3]->Uint32Value(currentContext).FromJust(), args[4]->Uint32Value(currentContext).FromJust());

  args.GetReturnValue().Set(Boolean::New(isolate, result));
}


void init(Local<Object> exports) {
  NODE_SET_METHOD(exports, "verify", verify);
}

NODE_MODULE(equihashverify, init)
