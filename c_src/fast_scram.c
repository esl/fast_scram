/*
 * fast-pbkdf2 - Optimal PBKDF2-HMAC calculation
 * Written in 2015 by Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "erl_nif.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#if defined(__GNUC__)
#include <sys/types.h>
#endif

#include <openssl/sha.h>

/* --- Common useful things --- */

static inline void write32_be(uint32_t n, uint8_t out[4])
{
#if defined(__GNUC__) && __GNUC__ >= 4 && __BYTE_ORDER == __LITTLE_ENDIAN
  *(uint32_t *)(out) = __builtin_bswap32(n);
#else
  out[0] = (n >> 24) & 0xff;
  out[1] = (n >> 16) & 0xff;
  out[2] = (n >> 8) & 0xff;
  out[3] = n & 0xff;
#endif
}

static inline void write64_be(uint64_t n, uint8_t out[8])
{
#if defined(__GNUC__) &&  __GNUC__ >= 4 && __BYTE_ORDER == __LITTLE_ENDIAN
  *(uint64_t *)(out) = __builtin_bswap64(n);
#else
  write32_be((n >> 32) & 0xffffffff, out);
  write32_be(n & 0xffffffff, out + 4);
#endif
}

/* Prepare block (of blocksz bytes) to contain md padding denoting a msg-size
 * message (in bytes).  block has a prefix of used bytes.
 * Message length is expressed in 32 bits (so suitable for all sha1 and sha2 algorithms). */
static inline void md_pad(uint8_t *block, size_t blocksz, size_t used, size_t msg)
{
  memset(block + used, 0, blocksz - used - 4);
  block[used] = 0x80;
  block += blocksz - 4;
  write32_be((uint32_t) (msg * 8), block);
}

/* Internal function/type names for hash-specific things. */
#define HMAC_CTX(_name) HMAC_ ## _name ## _ctx
#define HMAC_INIT(_name) HMAC_ ## _name ## _init
#define HMAC_UPDATE(_name) HMAC_ ## _name ## _update
#define HMAC_FINAL(_name) HMAC_ ## _name ## _final

#define PBKDF2_F(_name) pbkdf2_f_ ## _name
#define PBKDF2(_name) pbkdf2_ ## _name

/* This macro expands to decls for the whole implementation for a given
 * hash function.  Arguments are:
 *
 * _name like 'sha1', added to symbol names                         (e.g. sha256)
 * _blocksz block size, in bytes                                    (e.g. SHA256_CBLOCK)
 * _hashsz digest output, in bytes                                  (e.g. SHA256_DIGEST_LENGTH)
 * _ctx hash context type                                           (e.g. SHA256_Init)
 * _init hash context initialisation function                       (e.g. SHA256_Update)
 *    args: (_ctx *c)
 * _update hash context update function                             (e.g. SHA256_Update)
 *    args: (_ctx *c, const void *data, size_t ndata)
 * _final hash context finish function                              (e.g. SHA256_Final)
 *    args: (void *out, _ctx *c)
 * _xform hash context raw block update function                    (e.g. SHA256_Transform)
 *    args: (_ctx *c, const void *data)
 * _xcpy hash context raw copy function (only need copy hash state) (e.g. sha256_cpy)
 *    args: (_ctx * restrict out, const _ctx *restrict in)
 * _xtract hash context state extraction                            (e.g. sha256_extract)
 *    args: args (_ctx *restrict c, uint8_t *restrict out)
 * _xxor hash context xor function (only need xor hash state)       (e.g. sha256_xor)
 *    args: (_ctx *restrict out, const _ctx *restrict in)
 *
 * The resulting function is named PBKDF2(_name).
 */
#define DECL_PBKDF2(_name, _blocksz, _hashsz, _ctx,                           \
                    _init, _update, _xform, _final, _xcpy, _xtract, _xxor)    \
                                                                              \
  typedef struct {                                                            \
    _ctx inner;                                                               \
    _ctx outer;                                                               \
  } HMAC_CTX(_name);                                                          \
                                                                              \
  static inline void HMAC_INIT(_name)(HMAC_CTX(_name) *ctx,                   \
                                      const uint8_t *key, size_t nkey)        \
  {                                                                           \
    /* Prepare key: */                                                        \
    uint8_t k[_blocksz];                                                      \
                                                                              \
    /* Shorten long keys. */                                                  \
    if (nkey > _blocksz)                                                      \
    {                                                                         \
      _init(&ctx->inner);                                                     \
      _update(&ctx->inner, key, nkey);                                        \
      _final(k, &ctx->inner);                                                 \
      key = k;                                                                \
      nkey = _hashsz;                                                         \
    }                                                                         \
                                                                              \
    /* Standard doesn't cover case where blocksz < hashsz. */                 \
    assert(nkey <= _blocksz);                                                 \
                                                                              \
    /* Right zero-pad short keys. */                                          \
    if (k != key)                                                             \
      memcpy(k, key, nkey);                                                   \
    if (_blocksz > nkey)                                                      \
      memset(k + nkey, 0, _blocksz - nkey);                                   \
                                                                              \
    /* Start inner hash computation */                                        \
    uint8_t blk_inner[_blocksz];                                              \
    uint8_t blk_outer[_blocksz];                                              \
                                                                              \
    for (size_t i = 0; i < _blocksz; i++)                                     \
    {                                                                         \
      blk_inner[i] = 0x36 ^ k[i];                                             \
      blk_outer[i] = 0x5c ^ k[i];                                             \
    }                                                                         \
                                                                              \
    _init(&ctx->inner);                                                       \
    _update(&ctx->inner, blk_inner, sizeof blk_inner);                        \
                                                                              \
    /* And outer. */                                                          \
    _init(&ctx->outer);                                                       \
    _update(&ctx->outer, blk_outer, sizeof blk_outer);                        \
  }                                                                           \
                                                                              \
  static inline void HMAC_UPDATE(_name)(HMAC_CTX(_name) *ctx,                 \
                                        const void *data, size_t ndata)       \
  {                                                                           \
    _update(&ctx->inner, data, ndata);                                        \
  }                                                                           \
                                                                              \
  static inline void HMAC_FINAL(_name)(HMAC_CTX(_name) *ctx,                  \
                                       uint8_t out[_hashsz])                  \
  {                                                                           \
    _final(out, &ctx->inner);                                                 \
    _update(&ctx->outer, out, _hashsz);                                       \
    _final(out, &ctx->outer);                                                 \
  }                                                                           \
                                                                              \
  /* --- PBKDF2 --- */                                                        \
  static inline void PBKDF2_F(_name)(const HMAC_CTX(_name) *startctx,         \
                                     const uint8_t *salt, size_t nsalt,       \
                                     uint32_t iterations,                     \
                                     uint8_t *out)                            \
  {                                                                           \
    uint8_t countbuf[4];                                                      \
    write32_be((uint32_t)1, countbuf);                                        \
                                                                              \
    /* Prepare loop-invariant padding block. */                               \
    uint8_t Ublock[_blocksz];                                                 \
    md_pad(Ublock, _blocksz, _hashsz, _blocksz + _hashsz);                    \
                                                                              \
    /* First iteration:                                                       \
     *   U_1 = PRF(P, S || INT_32_BE(i))                                      \
     */                                                                       \
    HMAC_CTX(_name) ctx = *startctx;                                          \
    HMAC_UPDATE(_name)(&ctx, salt, nsalt);                                    \
    HMAC_UPDATE(_name)(&ctx, countbuf, sizeof countbuf);                      \
    HMAC_FINAL(_name)(&ctx, Ublock);                                          \
    _ctx result = ctx.outer;                                                  \
                                                                              \
    /* Subsequent iterations:                                                 \
     *   U_c = PRF(P, U_{c-1})                                                \
     */                                                                       \
    for (uint32_t i = 1; i < iterations; i++)                                 \
    {                                                                         \
      /* Complete inner hash with previous U */                               \
      _xcpy(&ctx.inner, &startctx->inner);                                    \
      _xform(&ctx.inner, Ublock);                                             \
      _xtract(&ctx.inner, Ublock);                                            \
      /* Complete outer hash with inner output */                             \
      _xcpy(&ctx.outer, &startctx->outer);                                    \
      _xform(&ctx.outer, Ublock);                                             \
      _xtract(&ctx.outer, Ublock);                                            \
      _xxor(&result, &ctx.outer);                                             \
    }                                                                         \
                                                                              \
    /* Reform result into output buffer. */                                   \
    _xtract(&result, out);                                                    \
  }                                                                           \
                                                                              \
  static inline void PBKDF2(_name)(const uint8_t *pw, size_t npw,             \
                     const uint8_t *salt, size_t nsalt,                       \
                     uint32_t iterations,                                     \
                     uint8_t *out)                                            \
  {                                                                           \
    assert(iterations);                                                       \
    assert(out);                                                              \
                                                                              \
    /* Starting point for inner loop. */                                      \
    HMAC_CTX(_name) ctx;                                                      \
    HMAC_INIT(_name)(&ctx, pw, npw);                                          \
                                                                              \
    uint8_t block[_hashsz];                                                   \
    PBKDF2_F(_name)(&ctx, salt, nsalt, iterations, block);                    \
                                                                              \
    memcpy(out, block, _hashsz);                                              \
  }


static inline void sha1_extract(SHA_CTX *restrict ctx, uint8_t *restrict out)
{
  write32_be(ctx->h0, out);
  write32_be(ctx->h1, out + 4);
  write32_be(ctx->h2, out + 8);
  write32_be(ctx->h3, out + 12);
  write32_be(ctx->h4, out + 16);
}

static inline void sha1_cpy(SHA_CTX *restrict out, const SHA_CTX *restrict in)
{
  out->h0 = in->h0;
  out->h1 = in->h1;
  out->h2 = in->h2;
  out->h3 = in->h3;
  out->h4 = in->h4;
}

static inline void sha1_xor(SHA_CTX *restrict out, const SHA_CTX *restrict in)
{
  out->h0 ^= in->h0;
  out->h1 ^= in->h1;
  out->h2 ^= in->h2;
  out->h3 ^= in->h3;
  out->h4 ^= in->h4;
}

DECL_PBKDF2(sha1,
            SHA_CBLOCK,
            SHA_DIGEST_LENGTH,
            SHA_CTX,
            SHA1_Init,
            SHA1_Update,
            SHA1_Transform,
            SHA1_Final,
            sha1_cpy,
            sha1_extract,
            sha1_xor)

static inline void sha224_extract(SHA256_CTX *restrict ctx, uint8_t *restrict out)
{
  write32_be(ctx->h[0], out);
  write32_be(ctx->h[1], out + 4);
  write32_be(ctx->h[2], out + 8);
  write32_be(ctx->h[3], out + 12);
  write32_be(ctx->h[4], out + 16);
  write32_be(ctx->h[5], out + 20);
  write32_be(ctx->h[6], out + 24);
}

static inline void sha256_extract(SHA256_CTX *restrict ctx, uint8_t *restrict out)
{
  write32_be(ctx->h[0], out);
  write32_be(ctx->h[1], out + 4);
  write32_be(ctx->h[2], out + 8);
  write32_be(ctx->h[3], out + 12);
  write32_be(ctx->h[4], out + 16);
  write32_be(ctx->h[5], out + 20);
  write32_be(ctx->h[6], out + 24);
  write32_be(ctx->h[7], out + 28);
}

static inline void sha256_cpy(SHA256_CTX *restrict out, const SHA256_CTX *restrict in)
{
  out->h[0] = in->h[0];
  out->h[1] = in->h[1];
  out->h[2] = in->h[2];
  out->h[3] = in->h[3];
  out->h[4] = in->h[4];
  out->h[5] = in->h[5];
  out->h[6] = in->h[6];
  out->h[7] = in->h[7];
}

static inline void sha256_xor(SHA256_CTX *restrict out, const SHA256_CTX *restrict in)
{
  out->h[0] ^= in->h[0];
  out->h[1] ^= in->h[1];
  out->h[2] ^= in->h[2];
  out->h[3] ^= in->h[3];
  out->h[4] ^= in->h[4];
  out->h[5] ^= in->h[5];
  out->h[6] ^= in->h[6];
  out->h[7] ^= in->h[7];
}

DECL_PBKDF2(sha224,
            SHA256_CBLOCK,
            SHA224_DIGEST_LENGTH,
            SHA256_CTX,
            SHA224_Init,
            SHA224_Update,
            SHA256_Transform,
            SHA224_Final,
            sha256_cpy,
            sha224_extract,
            sha256_xor)

DECL_PBKDF2(sha256,
            SHA256_CBLOCK,
            SHA256_DIGEST_LENGTH,
            SHA256_CTX,
            SHA256_Init,
            SHA256_Update,
            SHA256_Transform,
            SHA256_Final,
            sha256_cpy,
            sha256_extract,
            sha256_xor)

static inline void sha384_extract(SHA512_CTX *restrict ctx, uint8_t *restrict out)
{
  write64_be(ctx->h[0], out);
  write64_be(ctx->h[1], out + 8);
  write64_be(ctx->h[2], out + 16);
  write64_be(ctx->h[3], out + 24);
  write64_be(ctx->h[4], out + 32);
  write64_be(ctx->h[5], out + 40);
}

static inline void sha512_extract(SHA512_CTX *restrict ctx, uint8_t *restrict out)
{
  write64_be(ctx->h[0], out);
  write64_be(ctx->h[1], out + 8);
  write64_be(ctx->h[2], out + 16);
  write64_be(ctx->h[3], out + 24);
  write64_be(ctx->h[4], out + 32);
  write64_be(ctx->h[5], out + 40);
  write64_be(ctx->h[6], out + 48);
  write64_be(ctx->h[7], out + 56);
}

static inline void sha512_cpy(SHA512_CTX *restrict out, const SHA512_CTX *restrict in)
{
  out->h[0] = in->h[0];
  out->h[1] = in->h[1];
  out->h[2] = in->h[2];
  out->h[3] = in->h[3];
  out->h[4] = in->h[4];
  out->h[5] = in->h[5];
  out->h[6] = in->h[6];
  out->h[7] = in->h[7];
}

static inline void sha512_xor(SHA512_CTX *restrict out, const SHA512_CTX *restrict in)
{
  out->h[0] ^= in->h[0];
  out->h[1] ^= in->h[1];
  out->h[2] ^= in->h[2];
  out->h[3] ^= in->h[3];
  out->h[4] ^= in->h[4];
  out->h[5] ^= in->h[5];
  out->h[6] ^= in->h[6];
  out->h[7] ^= in->h[7];
}

DECL_PBKDF2(sha384,
            SHA512_CBLOCK,
            SHA384_DIGEST_LENGTH,
            SHA512_CTX,
            SHA384_Init,
            SHA384_Update,
            SHA512_Transform,
            SHA384_Final,
            sha512_cpy,
            sha384_extract,
            sha512_xor)

DECL_PBKDF2(sha512,
            SHA512_CBLOCK,
            SHA512_DIGEST_LENGTH,
            SHA512_CTX,
            SHA512_Init,
            SHA512_Update,
            SHA512_Transform,
            SHA512_Final,
            sha512_cpy,
            sha512_extract,
            sha512_xor)

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
    return 0;
}

static int reload(ErlNifEnv* env, void** priv, ERL_NIF_TERM info)
{
    return 0;
}

static int upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM info)
{
    return load(env, priv, info);
}

static void unload(ErlNifEnv* env, void* priv)
{
    return;
}

ERL_NIF_TERM mk_error(ErlNifEnv* env, const char *error_msg)
{
    return enif_make_tuple2(
            env,
            enif_make_atom(env, "error"),
            enif_make_atom(env, error_msg)
            );
}

static ERL_NIF_TERM
hi_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int hash_number;
    if (!enif_get_uint(env, argv[0], &hash_number))
        return mk_error(env, "bad_hash");

    ErlNifBinary password;
    if (!enif_inspect_binary(env, argv[1], &password))
        return mk_error(env, "bad_password");

    ErlNifBinary salt;
    if (!enif_inspect_binary(env, argv[2], &salt))
        return mk_error(env, "bad_salt");

    int iteration_count;
    if (!enif_get_int(env, argv[3], &iteration_count))
        return mk_error(env, "bad_count");
    if (iteration_count <= 0)
        return mk_error(env, "bad_count");

    /** Calculates PBKDF2-HMAC-SHA
     *  @p npw bytes at @p pw are the password input.
     *  @p nsalt bytes at @p salt are the salt input.
     *  @p iterations is the PBKDF2 iteration count and must be non-zero.
     */
    ERL_NIF_TERM result;
    unsigned char *output;
    switch (hash_number)
    {
        case 1:
            output = enif_make_new_binary(env, SHA_DIGEST_LENGTH, &result);
            PBKDF2(sha1)(
                    password.data, password.size,
                    salt.data, salt.size,
                    iteration_count,
                    output);
            break;
        case 224:
            output = enif_make_new_binary(env, SHA224_DIGEST_LENGTH, &result);
            PBKDF2(sha224)(
                    password.data, password.size,
                    salt.data, salt.size,
                    iteration_count,
                    output);
            break;
        case 256:
            output = enif_make_new_binary(env, SHA256_DIGEST_LENGTH, &result);
            PBKDF2(sha256)(
                    password.data, password.size,
                    salt.data, salt.size,
                    iteration_count,
                    output);
            break;
        case 384:
            output = enif_make_new_binary(env, SHA384_DIGEST_LENGTH, &result);
            PBKDF2(sha384)(
                    password.data, password.size,
                    salt.data, salt.size,
                    iteration_count,
                    output);
            break;
        case 512:
            output = enif_make_new_binary(env, SHA512_DIGEST_LENGTH, &result);
            PBKDF2(sha512)(
                    password.data, password.size,
                    salt.data, salt.size,
                    iteration_count,
                    output);
            break;
        default:
            return enif_make_badarg(env);
    }
    return result;
}

static ErlNifFunc fastpbkdf2_nif_funcs[] = {
    {"hi", 4, hi_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND}
};

ERL_NIF_INIT(fast_scram, fastpbkdf2_nif_funcs, load, reload, upgrade, unload);
