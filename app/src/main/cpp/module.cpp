#include <android/log.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <fstream>
#include <sys/mman.h>
#include <filesystem>
#include "zygisk.hpp"
#include "dobby.h"
#include "json.hpp"
#include "lsplant.hpp"
#include "elf_util.h"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "LSPlantDemo/Native", __VA_ARGS__)

#define _uintval(p)               reinterpret_cast<uintptr_t>(p)
#define _ptr(p)                   reinterpret_cast<void *>(p)
#define _align_up(x, n)           (((x) + ((n) - 1)) & ~((n) - 1))
#define _align_down(x, n)         ((x) & -(n))
#define _page_size                4096
#define _page_align(n)            _align_up(static_cast<uintptr_t>(n), _page_size)
#define _ptr_align(x)             _ptr(_align_down(reinterpret_cast<uintptr_t>(x), _page_size))
#define _make_rwx(p, n)           ::mprotect(_ptr_align(p), \
                                              _page_align(_uintval(p) + n) != _page_align(_uintval(p)) ? _page_align(n) + _page_size : _page_align(n), \
                                              PROT_READ | PROT_WRITE | PROT_EXEC)

void* InlineHooker(void* target, void* hooker) {
  _make_rwx(target, _page_size);
  void* origin_call;
  if (DobbyHook(target, hooker, &origin_call) == 0) {
    return origin_call;
  } else {
    return nullptr;
  }
}

bool InlineUnhooker(void* func) {
  return DobbyDestroy(func) == 0;
}

static void doHook(JNIEnv *env) {
  SandHook::ElfImg art("libart.so");

#if !defined(__i386__)
    dobby_enable_near_branch_trampoline();
#endif

    lsplant::InitInfo initInfo{
      .inline_hooker = InlineHooker,
      .inline_unhooker = InlineUnhooker,
      .art_symbol_resolver = [&art](std::string_view symbol) -> void* {
        return art.getSymbAddress(symbol);
      },
      .art_symbol_prefix_resolver = [&art](auto symbol) {
        return art.getSymbPrefixFirstOffset(symbol);
      },
    };
    bool ret = lsplant::Init(env, initInfo);
    if (ret) {
      LOGD("LSPlant init done");
    } else {
      LOGD("LSPlant init failed");
    }
}

class LSPlantDemo : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
      doHook(env);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
};

REGISTER_ZYGISK_MODULE(LSPlantDemo)