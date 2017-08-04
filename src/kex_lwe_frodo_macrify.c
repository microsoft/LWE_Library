/********************************************************************************************
* Frodo: a post-quantum key exchange based on the Learning with Errors (LWE) problem.
*
* Abstract: key exchange functions
*********************************************************************************************/


int MACRIFY(OQS_KEX_lwe_frodo_alice_0)(OQS_KEX *k, void **alice_priv, uint8_t **alice_msg, size_t *alice_msg_len)
{
    int ret;
    struct oqs_kex_lwe_frodo_params *params = (struct oqs_kex_lwe_frodo_params*)k->params;
    uint16_t b[PARAMS_N * PARAMS_NBAR] = {0}, e[PARAMS_N * PARAMS_NBAR] = {0};

    *alice_priv = NULL;
    *alice_msg = NULL;

    // Allocate private key and outgoing message
#if !defined(USE_AVX2)
    *alice_priv = malloc(params->n * params->nbar * sizeof(uint16_t));
#else
    *alice_priv = _mm_malloc(params->n * params->nbar * sizeof(uint16_t), 32);
#endif
    if (*alice_priv == NULL) {
        goto err;
    }
    *alice_msg = malloc(params->pub_len);
    if (*alice_msg == NULL) {
        goto err;
    }

    // Generate S and E
    ret = oqs_kex_lwe_frodo_sample_n(*alice_priv, params->n * params->nbar, params, k->rand);
    if (ret != 1) {
        goto err;
    }
    ret = oqs_kex_lwe_frodo_sample_n(e, params->n * params->nbar, params, k->rand);
    if (ret != 1) {
        goto err;
    }

    // Compute B = AS + E
    ret = MACRIFY(oqs_kex_lwe_frodo_mul_add_as_plus_e_on_the_fly)(b, *alice_priv, e, params);
    if (ret != 1) {
        goto err;
    }
    oqs_kex_lwe_frodo_pack(*alice_msg, params->pub_len, b, params->n * params->nbar, params->log2_q);

    *alice_msg_len = params->pub_len;

    ret = 1;
    return ret;                

err:
    ret = 0;
    free(*alice_msg);
    *alice_msg = NULL;
    free(*alice_priv);
    *alice_priv = NULL;
    return ret;
}


int MACRIFY(OQS_KEX_lwe_frodo_bob)(OQS_KEX *k, const uint8_t *alice_msg, const size_t alice_msg_len, uint8_t **bob_msg, size_t *bob_msg_len, uint8_t **key, size_t *key_len) 
{
    int ret;
    struct oqs_kex_lwe_frodo_params *params = (struct oqs_kex_lwe_frodo_params*)k->params;
    uint8_t *bob_rec = NULL;
    ALIGN_HEADER(32) uint16_t bob_priv[PARAMS_NBAR * PARAMS_N] ALIGN_FOOTER(32) = {0};        
    ALIGN_HEADER(32) uint16_t b[PARAMS_NBAR * PARAMS_N] ALIGN_FOOTER(32) = {0};
    uint16_t bprime[PARAMS_NBAR * PARAMS_N] = {0};
    uint16_t eprime[PARAMS_NBAR * PARAMS_N] = {0};
    uint16_t eprimeprime[PARAMS_NBAR * PARAMS_NBAR] = {0};
    uint16_t v[PARAMS_NBAR * PARAMS_NBAR] = {0};
    *bob_msg = NULL;
    *key = NULL;

    // Check length of other party's public key
    if (alice_msg_len != params->pub_len) {
        goto err;
    }

    // Allocate outgoing message and key
    *bob_msg = malloc(params->pub_len + params->rec_hint_len);
    if (*bob_msg == NULL) {
        goto err;
    }
    bob_rec = *bob_msg + params->pub_len;
    *key = malloc(params->key_bits >> 3);
    if (*key == NULL) {
        goto err;
    }

    // Generate S' and E'
    ret = oqs_kex_lwe_frodo_sample_n(bob_priv, params->n * params->nbar, params, k->rand);
    if (ret != 1) {
        goto err;
    }
    ret = oqs_kex_lwe_frodo_sample_n(eprime, params->n * params->nbar, params, k->rand);
    if (ret != 1) {
        goto err;
    }

    // Compute B' = S'A + E'
    ret = MACRIFY(oqs_kex_lwe_frodo_mul_add_sa_plus_e_on_the_fly)(bprime, bob_priv, eprime, params);
    if (ret != 1) {
        goto err;
    }
    oqs_kex_lwe_frodo_pack(*bob_msg, params->pub_len, bprime, params->n * params->nbar, params->log2_q);

    // Generate E''
    ret = oqs_kex_lwe_frodo_sample_n(eprimeprime, params->nbar * params->nbar, params, k->rand);
    if (ret != 1) {
        goto err;
    }

    // Unpack B
    oqs_kex_lwe_frodo_unpack(b, params->n * params->nbar, alice_msg, alice_msg_len, params->log2_q);

    // Compute V = S'B + E''
    MACRIFY(oqs_kex_lwe_frodo_mul_add_sb_plus_e)(v, b, bob_priv, eprimeprime);

    // Compute C = <V>_{2^B}
    MACRIFY(oqs_kex_lwe_frodo_crossround2)(bob_rec, v);

    // Compute K = round(V)_{2^B}
    MACRIFY(oqs_kex_lwe_frodo_round2)(*key, v);

    *bob_msg_len = params->pub_len + params->rec_hint_len;
    *key_len = params->key_bits >> 3;

    ret = 1;
    goto cleanup;

err:
    ret = 0;
    free(*bob_msg);
    *bob_msg = NULL;
    if (*key != NULL) {
        memset(*key, 0, params->key_bits >> 3);
    }
    free(*key);
    *key = NULL;

cleanup:
    memset(eprime, 0, PARAMS_NBAR * PARAMS_N * sizeof(uint16_t));           
    memset(eprimeprime, 0, PARAMS_NBAR * PARAMS_NBAR * sizeof(uint16_t));
    memset(v, 0, PARAMS_NBAR * PARAMS_NBAR * sizeof(uint16_t));
    return ret;
}


int MACRIFY(OQS_KEX_lwe_frodo_alice_1)(OQS_KEX *k, const void *alice_priv, const uint8_t *bob_msg, const size_t bob_msg_len, uint8_t **key, size_t *key_len) 
{
    int ret;
    struct oqs_kex_lwe_frodo_params *params = (struct oqs_kex_lwe_frodo_params*)k->params;
    uint16_t *bprime = NULL, *w = NULL;
    //uint16_t bprime[PARAMS_NBAR * PARAMS_N] = {0};
    //uint16_t w[PARAMS_NBAR * PARAMS_NBAR] = {0};
    *key = NULL;

    // Check length of other party's public key
    if (bob_msg_len != params->pub_len + params->rec_hint_len) {
        goto err;
    }

    // Allocate working values and session key
    bprime = malloc(params->n * params->nbar * sizeof(uint16_t));
    if (bprime == NULL) {
        goto err;
    }
    w = malloc(params->nbar * params->nbar * sizeof(uint16_t));
    if (w == NULL) {
        goto err;
    }
    *key = malloc(params->key_bits >> 3);
    if (*key == NULL) {
        goto err;
    }

    // Unpack B'
    oqs_kex_lwe_frodo_unpack(bprime, params->n * params->nbar, bob_msg, params->pub_len, params->log2_q);

    // Compute W = B'S
    MACRIFY(oqs_kex_lwe_frodo_mul_bs)(w, bprime, (uint16_t*)alice_priv);

    // Compute K = rec(B'S, C)
    const uint8_t *bob_rec = bob_msg + params->pub_len;
    MACRIFY(oqs_kex_lwe_frodo_reconcile)(*key, w, bob_rec);

    *key_len = params->key_bits >> 3;

    ret = 1;
    goto cleanup;
    //goto exit;

err:
    ret = 0;
    memset(key, 0, params->key_bits >> 3);
    free(*key);
    *key = NULL;

cleanup:
    free(w);
    free(bprime);

//exit:
    return ret;
}