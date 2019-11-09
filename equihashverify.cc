#include <nan.h>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include "crypto/equihash.h"

#include <vector>

using namespace node;
using namespace v8;

int verifyEH(const char *hdr, const std::vector<unsigned char> &soln, unsigned int n = 200, unsigned int k = 9){
  // Hash state
  crypto_generichash_blake2b_state state;
  EhInitialiseState(n, k, state);

  crypto_generichash_blake2b_update(&state, (const unsigned char*)hdr, 140);

  bool isValid;
  if (n == 96 && k == 3) {
      isValid = Eh96_3.IsValidSolution(state, soln);
  } else if (n == 200 && k == 9) {
      isValid = Eh200_9.IsValidSolution(state, soln);
  } else if (n == 144 && k == 5) {
      isValid = Eh144_5.IsValidSolution(state, soln);
  } else if (n == 192 && k == 7) {
      isValid = Eh192_7.IsValidSolution(state, soln);
  } else if (n == 96 && k == 5) {
      isValid = Eh96_5.IsValidSolution(state, soln);
  } else if (n == 48 && k == 5) {
      isValid = Eh48_5.IsValidSolution(state, soln);
  } else {
      throw std::invalid_argument("Unsupported Equihash parameters");
  }
  
  return isValid;
}

void verify(const FunctionCallbackInfo<Value>& args) {
  Isolate* isolate = args.GetIsolate();
  HandleScope scope(isolate);

  unsigned int n = 200;
  unsigned int k = 9;

  if (args.Length() < 2) {
    do {
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Wrong number of arguments")));
        return;
    } while (0);
  }

  Local<Object> header = args[0]->ToObject(isolate);
  Local<Object> solution = args[1]->ToObject(isolate);

  if (args.Length() == 4) {
    Local<Context> currentContext = isolate->GetCurrentContext();
    n = args[2]->Uint32Value(currentContext).FromJust();
    k = args[3]->Uint32Value(currentContext).FromJust();
  }

  if(!Buffer::HasInstance(header) || !Buffer::HasInstance(solution)) {
    do {
        isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Arguments should be buffer objects.")));
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

  bool result = verifyEH(hdr, vecSolution, n, k);
  args.GetReturnValue().Set(Boolean::New(isolate, result));
}


void init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "verify", verify);
}

NODE_MODULE(equihashverify, init)
