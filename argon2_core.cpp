#include "argon2/include/argon2.h"
#include <napi.h>
#include <cstdlib>
#include <cstring>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <malloc.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

// Detect explicit_bzero (glibc >= 2.25 and the BSDs) with nested #if guards so
// that __GLIBC_PREREQ is never evaluated on platforms that do not define it
// (e.g. macOS/Darwin), where doing so is a hard preprocessor error.
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 25)
#define ARGON_HAVE_EXPLICIT_BZERO 1
#endif
#elif defined(__OpenBSD__) || defined(__FreeBSD__)
#define ARGON_HAVE_EXPLICIT_BZERO 1
#endif

namespace
{

  void secure_wipe(void *ptr, size_t size)
  {
    if (!ptr || size == 0)
      return;
#if defined(_WIN32)
    SecureZeroMemory(ptr, size);
#elif defined(ARGON_HAVE_EXPLICIT_BZERO)
    explicit_bzero(ptr, size);
#else
    volatile char *p = static_cast<volatile char *>(ptr);
    while (size--)
      *p++ = 0;
#endif
  }

  // Best effort: prevents secrets from hitting swap. Failure is not fatal —
  // RLIMIT_MEMLOCK defaults are far below common m_cost values, and the
  // memory is wiped before release regardless.
  void lock_memory(void *ptr, size_t size)
  {
    if (!ptr || size == 0)
      return;
#ifdef _WIN32
    VirtualLock(ptr, size);
#else
    mlock(ptr, size);
#endif
  }

  void unlock_memory(void *ptr, size_t size)
  {
    if (!ptr || size == 0)
      return;
#ifdef _WIN32
    VirtualUnlock(ptr, size);
#else
    munlock(ptr, size);
#endif
  }

  constexpr size_t HUGE_PAGE_SIZE = size_t{2} * 1024 * 1024;

  // Page-aligned so madvise() accepts the range; 2 MiB-aligned for large
  // blocks so transparent huge pages can back the Argon2 matrix (fewer TLB
  // misses during the memory-hard passes).
  int custom_allocate(uint8_t **memory, size_t bytes_to_allocate)
  {
    const size_t alignment = bytes_to_allocate >= HUGE_PAGE_SIZE ? HUGE_PAGE_SIZE : 4096;
#ifdef _WIN32
    *memory = static_cast<uint8_t *>(_aligned_malloc(bytes_to_allocate, alignment));
    if (!*memory)
      return -1;
#else
    if (posix_memalign(reinterpret_cast<void **>(memory), alignment, bytes_to_allocate) != 0)
    {
      *memory = nullptr;
      return -1;
    }
#if defined(__linux__)
#ifdef MADV_DONTDUMP
    madvise(*memory, bytes_to_allocate, MADV_DONTDUMP);
#endif
#ifdef MADV_HUGEPAGE
    if (bytes_to_allocate >= HUGE_PAGE_SIZE)
      madvise(*memory, bytes_to_allocate, MADV_HUGEPAGE);
#endif
#endif
#endif
    lock_memory(*memory, bytes_to_allocate);
    return 0;
  }

  // No wipe here: the reference core's free_memory() already wipes the matrix
  // before invoking this callback (clear_internal_memory in core.c), so a
  // second pass would just double the memset cost. SecureBuffer wipes its own
  // contents before calling this.
  void custom_free(uint8_t *memory, size_t bytes_to_allocate)
  {
    if (!memory)
      return;
    unlock_memory(memory, bytes_to_allocate);
#ifdef _WIN32
    _aligned_free(memory);
#else
    free(memory);
#endif
  }

  bool constant_time_compare(const uint8_t *a, const uint8_t *b, size_t length)
  {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < length; i++)
    {
      result |= a[i] ^ b[i];
    }
    return result == 0;
  }

  // Off-heap copy of a sensitive Napi buffer: page-aligned, excluded from
  // core dumps, mlock'ed (best effort) and wiped on destruction.
  struct SecureBuffer
  {
    uint8_t *data = nullptr;
    size_t size = 0;
    bool ok = true;

    explicit SecureBuffer(const Napi::Buffer<uint8_t> &napi_buf)
    {
      size = napi_buf.ByteLength();
      if (size == 0)
        return;
      if (custom_allocate(&data, size) != 0)
      {
        ok = false;
        return;
      }
      std::memcpy(data, napi_buf.Data(), size);
    }

    ~SecureBuffer()
    {
      if (data)
      {
        secure_wipe(data, size);
        custom_free(data, size);
      }
    }

    SecureBuffer(const SecureBuffer &) = delete;
    SecureBuffer &operator=(const SecureBuffer &) = delete;
    SecureBuffer(SecureBuffer &&) = delete;
    SecureBuffer &operator=(SecureBuffer &&) = delete;
  };

  class HashWorker final : public Napi::AsyncWorker
  {
  public:
    HashWorker(const Napi::Env &env, const Napi::Buffer<uint8_t> &plain_buf,
               const Napi::Buffer<uint8_t> &salt_buf, const Napi::Buffer<uint8_t> &secret_buf,
               const Napi::Buffer<uint8_t> &ad_buf, uint32_t hash_length,
               uint32_t memory_cost, uint32_t time_cost, uint32_t parallelism,
               uint32_t version, uint32_t type)
        : AsyncWorker{env, "argon2:HashWorker"}, deferred{env},
          plain{plain_buf}, secret{secret_buf},
          salt{salt_buf.Data(), salt_buf.Data() + salt_buf.ByteLength()},
          ad{ad_buf.Data(), ad_buf.Data() + ad_buf.ByteLength()},
          hash_length{hash_length}, memory_cost{memory_cost}, time_cost{time_cost},
          parallelism{parallelism}, version{version}, type{static_cast<argon2_type>(type)} {}

    ~HashWorker() override
    {
      secure_wipe(hash.data(), hash.size());
    }

    auto GetPromise() -> Napi::Promise { return deferred.Promise(); }

  protected:
    void Execute() override
    {
      if (!plain.ok || !secret.ok)
      {
        SetError("Failed to allocate secure memory for sensitive data");
        return;
      }

      hash.resize(hash_length);
      argon2_context ctx;
      ctx.out = hash.data();
      ctx.outlen = static_cast<uint32_t>(hash.size());
      ctx.pwd = plain.data;
      ctx.pwdlen = static_cast<uint32_t>(plain.size);
      ctx.salt = salt.data();
      ctx.saltlen = static_cast<uint32_t>(salt.size());
      ctx.secret = secret.data;
      ctx.secretlen = static_cast<uint32_t>(secret.size);
      ctx.ad = ad.empty() ? nullptr : ad.data();
      ctx.adlen = static_cast<uint32_t>(ad.size());
      ctx.m_cost = memory_cost;
      ctx.t_cost = time_cost;
      ctx.lanes = parallelism;
      ctx.threads = parallelism;
      ctx.allocate_cbk = custom_allocate;
      ctx.free_cbk = custom_free;
      ctx.flags = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET;
      ctx.version = version;

      if (const int result = argon2_ctx(&ctx, type); result != ARGON2_OK)
      {
        SetError(argon2_error_message(result));
      }
    }

    void OnOK() override
    {
      deferred.Resolve(Napi::Buffer<uint8_t>::Copy(Env(), hash.data(), hash.size()));
    }

    void OnError(const Napi::Error &err) override
    {
      deferred.Reject(err.Value());
    }

  private:
    using ustring = std::vector<uint8_t>;
    Napi::Promise::Deferred deferred;
    ustring hash = {};
    SecureBuffer plain;
    SecureBuffer secret;
    ustring salt;
    ustring ad;
    uint32_t hash_length, memory_cost, time_cost, parallelism, version;
    argon2_type type;
  };

  class VerifyWorker final : public Napi::AsyncWorker
  {
  public:
    VerifyWorker(const Napi::Env &env, const Napi::Buffer<uint8_t> &plain_buf,
                 const Napi::Buffer<uint8_t> &expected_hash_buf, const Napi::Buffer<uint8_t> &salt_buf,
                 const Napi::Buffer<uint8_t> &secret_buf, const Napi::Buffer<uint8_t> &ad_buf,
                 uint32_t memory_cost, uint32_t time_cost, uint32_t parallelism, uint32_t version, uint32_t type)
        : AsyncWorker{env, "argon2:VerifyWorker"}, deferred{env},
          plain{plain_buf}, secret{secret_buf},
          expected_hash{expected_hash_buf.Data(), expected_hash_buf.Data() + expected_hash_buf.ByteLength()},
          salt{salt_buf.Data(), salt_buf.Data() + salt_buf.ByteLength()},
          ad{ad_buf.Data(), ad_buf.Data() + ad_buf.ByteLength()},
          memory_cost{memory_cost}, time_cost{time_cost}, parallelism{parallelism}, version{version}, type{static_cast<argon2_type>(type)} {}

    ~VerifyWorker() override
    {
      secure_wipe(computed_hash.data(), computed_hash.size());
    }

    auto GetPromise() -> Napi::Promise { return deferred.Promise(); }

  protected:
    void Execute() override
    {
      if (!plain.ok || !secret.ok)
      {
        SetError("Failed to allocate secure memory for sensitive data");
        return;
      }

      computed_hash.resize(expected_hash.size());

      argon2_context ctx;
      ctx.out = computed_hash.data();
      ctx.outlen = static_cast<uint32_t>(computed_hash.size());
      ctx.pwd = plain.data;
      ctx.pwdlen = static_cast<uint32_t>(plain.size);
      ctx.salt = salt.data();
      ctx.saltlen = static_cast<uint32_t>(salt.size());
      ctx.secret = secret.data;
      ctx.secretlen = static_cast<uint32_t>(secret.size);
      ctx.ad = ad.empty() ? nullptr : ad.data();
      ctx.adlen = static_cast<uint32_t>(ad.size());
      ctx.m_cost = memory_cost;
      ctx.t_cost = time_cost;
      ctx.lanes = parallelism;
      ctx.threads = parallelism;
      ctx.allocate_cbk = custom_allocate;
      ctx.free_cbk = custom_free;
      ctx.flags = ARGON2_FLAG_CLEAR_PASSWORD | ARGON2_FLAG_CLEAR_SECRET;
      ctx.version = version;

      if (const int result = argon2_ctx(&ctx, type); result != ARGON2_OK)
      {
        SetError(argon2_error_message(result));
        return;
      }

      match = constant_time_compare(computed_hash.data(), expected_hash.data(), expected_hash.size());
    }

    void OnOK() override
    {
      deferred.Resolve(Napi::Boolean::New(Env(), match));
    }

    void OnError(const Napi::Error &err) override
    {
      deferred.Reject(err.Value());
    }

  private:
    using ustring = std::vector<uint8_t>;
    Napi::Promise::Deferred deferred;
    SecureBuffer plain;
    SecureBuffer secret;
    ustring computed_hash = {};
    ustring expected_hash;
    ustring salt;
    ustring ad;
    uint32_t memory_cost, time_cost, parallelism, version;
    argon2_type type;
    bool match = false;
  };

  auto Reject(const Napi::Env &env, const Napi::Error &error) -> Napi::Promise
  {
    auto deferred = Napi::Promise::Deferred::New(env);
    deferred.Reject(error.Value());
    return deferred.Promise();
  }

  bool GetBuffer(const Napi::Object &args, const char *name, Napi::Buffer<uint8_t> &out)
  {
    const auto value = args.Get(name);
    if (!value.IsBuffer())
      return false;
    out = value.As<Napi::Buffer<uint8_t>>();
    return true;
  }

  bool GetUint32(const Napi::Object &args, const char *name, uint32_t &out)
  {
    const auto value = args.Get(name);
    if (!value.IsNumber())
      return false;
    out = value.As<Napi::Number>().Uint32Value();
    return true;
  }

  struct CommonArgs
  {
    Napi::Buffer<uint8_t> password, salt, secret, data;
    uint32_t m = 0, t = 0, p = 0, version = 0, type = 0;
  };

  bool ExtractCommonArgs(const Napi::Object &args, CommonArgs &out)
  {
    return GetBuffer(args, "password", out.password) &&
           GetBuffer(args, "salt", out.salt) &&
           GetBuffer(args, "secret", out.secret) &&
           GetBuffer(args, "data", out.data) &&
           GetUint32(args, "m", out.m) &&
           GetUint32(args, "t", out.t) &&
           GetUint32(args, "p", out.p) &&
           GetUint32(args, "version", out.version) &&
           GetUint32(args, "type", out.type);
  }

  auto Hash(const Napi::CallbackInfo &info) -> Napi::Value
  {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject())
    {
      return Reject(env, Napi::TypeError::New(env, "hash: expected an options object"));
    }
    const auto args = info[0].As<Napi::Object>();
    CommonArgs common;
    uint32_t hash_length = 0;
    if (!ExtractCommonArgs(args, common) || !GetUint32(args, "hashLength", hash_length))
    {
      return Reject(env, Napi::TypeError::New(env, "hash: invalid or missing option (expected Buffers and numbers)"));
    }
    auto *worker = new HashWorker{env, common.password, common.salt, common.secret, common.data,
                                  hash_length, common.m, common.t, common.p, common.version, common.type};
    worker->Queue();
    return worker->GetPromise();
  }

  auto Verify(const Napi::CallbackInfo &info) -> Napi::Value
  {
    Napi::Env env = info.Env();
    if (info.Length() < 1 || !info[0].IsObject())
    {
      return Reject(env, Napi::TypeError::New(env, "verify: expected an options object"));
    }
    const auto args = info[0].As<Napi::Object>();
    CommonArgs common;
    Napi::Buffer<uint8_t> expected_hash;
    if (!ExtractCommonArgs(args, common) || !GetBuffer(args, "expectedHash", expected_hash))
    {
      return Reject(env, Napi::TypeError::New(env, "verify: invalid or missing option (expected Buffers and numbers)"));
    }
    auto *worker = new VerifyWorker{env, common.password, expected_hash, common.salt, common.secret, common.data,
                                    common.m, common.t, common.p, common.version, common.type};
    worker->Queue();
    return worker->GetPromise();
  }

  auto init(Napi::Env env, Napi::Object exports) -> Napi::Object
  {
    exports["hash"] = Napi::Function::New(env, Hash);
    exports["verify"] = Napi::Function::New(env, Verify);
    return exports;
  }

} // namespace

NODE_API_MODULE(argon2_lib, init)
