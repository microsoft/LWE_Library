/********************************************************************************************
* Frodo: a post-quantum key exchange based on the Learning with Errors (LWE) problem.
*
* Abstract: matrix arithmetic functions required by the kex scheme
*********************************************************************************************/

//#define AES128_ECB

#include "malloc.h"
#if defined(AES128_ECB)
    #include "aes/aes.h"
#else
    #include "sha3/fips202.h"
#endif    


int MACRIFY(oqs_kex_lwe_frodo_mul_add_as_plus_e_on_the_fly)(uint16_t *out, const uint16_t *s, const uint16_t *e, struct oqs_kex_lwe_frodo_params *params) 
{ // Generate-and-multiply: generate matrix A (N x N) row-wise, multiply by s on the right.
  // Inputs: s, e (N x N_BAR)
  // Output: out = A*s + e (N x N_BAR)
    int i, j, k;
    int ret = 0;
    int16_t* A = NULL;                                               
    size_t A_len = PARAMS_N * PARAMS_N * sizeof(int16_t);

    A = calloc(1, A_len);
	if (A == NULL) {
		return ret;
	}  
       
#if defined(AES128_ECB)    // Matrix A generation using AES128-ECB, done per 128-bit block      
    for (i = 0; i < PARAMS_N; i++) {                        
        for (j = 0; j < PARAMS_N; j += PARAMS_STRIPE_STEP) {
            A[i*PARAMS_N + j] = i;                              // Loading values in the little-endian order
            A[i*PARAMS_N + j + 1] = j;                                  
        }
    }
    
    assert(params->seed_len == 16);
    void *aes_key_schedule = NULL;
    OQS_AES128_load_schedule(params->seed, &aes_key_schedule, 1);
    OQS_AES128_ECB_enc_sch((uint8_t*)A, A_len, aes_key_schedule, (uint8_t*)A);
#else    // Matrix A generation using cSHAKE128, done per 16*N-bit row   
    for (i = 0; i < PARAMS_N; i++) {
        cshake128_simple((unsigned char*)(A + i*PARAMS_N), (unsigned long long)(2*PARAMS_N), (uint16_t)i, params->seed, (unsigned long long)params->seed_len);
    }
#endif    
    memcpy(out, e, PARAMS_NBAR * PARAMS_N * sizeof(uint16_t));  

    for (i = 0; i < PARAMS_N; i++) {                            // Matrix multiplication-addition A*s + e
        for (k = 0; k < PARAMS_NBAR; k++) {
            uint16_t sum = 0;
            for (j = 0; j < PARAMS_N; j++) {                                
                sum += A[i*PARAMS_N + j] * s[j*PARAMS_NBAR + k];  
            }
            out[i*PARAMS_NBAR + k] += sum;                      // Adding e. No need to reduce modulo 2^15, extra bits are taken care of during packing later on.
        }
    }
    
#if defined(AES128_ECB)
    OQS_AES128_free_schedule(aes_key_schedule);
#endif
    return 1;
}


int MACRIFY(oqs_kex_lwe_frodo_mul_add_sa_plus_e_on_the_fly)(uint16_t *out, const uint16_t *s, const uint16_t *e, struct oqs_kex_lwe_frodo_params *params) 
{ // Generate-and-multiply: generate matrix A (N x N) column-wise, multiply by s' on the left.
  // Inputs: s', e' (N_BAR x N)
  // Output: out = s'*A + e' (N_BAR x N)
    int i, j, k;
    int ret = 0;
    int16_t* A = NULL;                                               
    size_t A_len = PARAMS_N * PARAMS_N * sizeof(int16_t);

    A = calloc(1, A_len);
	if (A == NULL) {
		return ret;
	}   
    
#if defined(AES128_ECB)    // Matrix A generation using AES128-ECB, done per 128-bit block         
    for (i = 0; i < PARAMS_N; i++) {                        
        for (j = 0; j < PARAMS_N; j += PARAMS_STRIPE_STEP) {
            A[i*PARAMS_N + j] = i;                              // Loading values in the little-endian order
            A[i*PARAMS_N + j + 1] = j;                                  
        }
    } 

    assert(params->seed_len == 16);
    void *aes_key_schedule = NULL;
    OQS_AES128_load_schedule(params->seed, &aes_key_schedule, 1);
    OQS_AES128_ECB_enc_sch((uint8_t*)A, A_len, aes_key_schedule, (uint8_t*)A);
#else    // Matrix A generation using cSHAKE128, done per 16*N-bit row
    for (i = 0; i < PARAMS_N; i++) {
        cshake128_simple((unsigned char*)(A + i*PARAMS_N), (unsigned long long)(2*PARAMS_N), (uint16_t)i, params->seed, (unsigned long long)params->seed_len);
    }
#endif
    memcpy(out, e, PARAMS_NBAR * PARAMS_N * sizeof(uint16_t));

    for (i = 0; i < PARAMS_N; i++) {                            // Matrix multiplication-addition A*s + e
        for (k = 0; k < PARAMS_NBAR; k++) {
            uint16_t sum = 0;
            for (j = 0; j < PARAMS_N; j++) {                                
                sum += A[j*PARAMS_N + i] * s[k*PARAMS_N + j];  
            }
            out[k*PARAMS_N + i] += sum;                         // Adding e. No need to reduce modulo 2^15, extra bits are taken care of during packing later on.
        }
    }
    
#if defined(AES128_ECB)
    OQS_AES128_free_schedule(aes_key_schedule);
#endif
    return 1;
}


void MACRIFY(oqs_kex_lwe_frodo_mul_bs)(uint16_t *out, const uint16_t *b, const uint16_t *s) 
{ // Multiply by s on the right
  // Inputs: b (N_BAR x N), s (N x N_BAR)
  // Output: out = b*s
    int i, j, k;

    for (i = 0; i < PARAMS_NBAR; i++) {
        for (j = 0; j < PARAMS_NBAR; j++) {
            out[i * PARAMS_NBAR + j] = 0;
            for (k = 0; k < PARAMS_N; k++) {
                out[i * PARAMS_NBAR + j] += b[i * PARAMS_N + k] * s[k*PARAMS_NBAR + j];
            }
            out[i * PARAMS_NBAR + j] = (uint32_t)(out[i * PARAMS_NBAR + j] << 17) >> 17;    // Fixed to params->q = 1 << 15)
        }
    }
}


void MACRIFY(oqs_kex_lwe_frodo_mul_add_sb_plus_e)(uint16_t *out, const uint16_t *b, const uint16_t *s, const uint16_t *e) 
{ // Multiply by s on the left
  // Inputs: b (N x N_BAR), s (N_BAR x N), e (N_BAR x N_BAR)
  // Output: out = s*b + e
    int i, j, k;

    for (k = 0; k < PARAMS_NBAR; k++) {
        for (i = 0; i < PARAMS_NBAR; i++) {
            out[k * PARAMS_NBAR + i] = e[k * PARAMS_NBAR + i];
            for (j = 0; j < PARAMS_N; j++) {
                out[k * PARAMS_NBAR + i] += s[k * PARAMS_N + j] * b[j * PARAMS_NBAR + i];
            }
            out[k * PARAMS_NBAR + i] = (uint32_t)(out[k * PARAMS_NBAR + i] << 17) >> 17;    // Fixed to params->q = 1 << 15)
        }
    }
}


void MACRIFY(oqs_kex_lwe_frodo_add)(uint32_t *out, const uint32_t *a, const uint32_t *b) 
{ // Add a and b
  // Inputs: a, b (N_BAR x N_BAR)
  // Output: c = a + b

    for (int i = 0; i < (PARAMS_NBAR * PARAMS_NBAR); i++) {
        out[i] = ((a[i] + b[i]) << 17) >> 17;    // Fixed to params->q = 1 << 15
    }
}


void MACRIFY(oqs_kex_lwe_frodo_sub)(uint32_t *out, const uint32_t *a, const uint32_t *b) 
{ // Subtract a and b
  // Inputs: a, b (N_BAR x N_BAR)
  // Output: c = a - b

    for (int i = 0; i < (PARAMS_NBAR * PARAMS_NBAR); i++) {
        out[i] = ((a[i] - b[i]) << 17) >> 17;    // Fixed to params->q = 1 << 15
    }
}


void MACRIFY(oqs_kex_lwe_frodo_round2)(unsigned char *out, uint16_t *in) 
{
    oqs_kex_lwe_frodo_key_round(in, PARAMS_NBAR * PARAMS_NBAR, PARAMS_LOG2Q - PARAMS_EXTRACTED_BITS);
    int i;

    for (i = 0; i < PARAMS_NBAR * PARAMS_NBAR; i++) {
        in[i] >>= PARAMS_LOG2Q - PARAMS_EXTRACTED_BITS;    // Drop bits that were zeroed out
    }

    // Out should have enough space for the key
    oqs_kex_lwe_frodo_pack(out, PARAMS_KEY_BITS / 8, in, PARAMS_NBAR * PARAMS_NBAR, PARAMS_EXTRACTED_BITS);
}


void MACRIFY(oqs_kex_lwe_frodo_crossround2)(unsigned char *out, const uint16_t *in) 
{
    int i;
    // Out should have enough space for N_BAR * N_BAR bits
    memset((unsigned char *)out, 0, PARAMS_REC_HINT_LENGTH);

    uint16_t whole = 1 << (PARAMS_LOG2Q - PARAMS_EXTRACTED_BITS);
    uint16_t half = whole >> 1;
    uint16_t mask = whole - 1;

    for (i = 0; i < PARAMS_NBAR * PARAMS_NBAR; i++) {
        uint16_t remainder = in[i] & mask;
        out[i / 8] += (remainder >= half) << (i % 8);
    }
}


void MACRIFY(oqs_kex_lwe_frodo_reconcile)(unsigned char *out, uint16_t *w, const unsigned char *hint) 
{
    oqs_kex_lwe_frodo_key_round_hints(w, PARAMS_NBAR * PARAMS_NBAR, PARAMS_LOG2Q - PARAMS_EXTRACTED_BITS, hint);
    int i;

    for (i = 0; i < PARAMS_NBAR * PARAMS_NBAR; i++) {
        w[i] >>= PARAMS_LOG2Q - PARAMS_EXTRACTED_BITS;    // Drop bits that were zeroed out
    }
    oqs_kex_lwe_frodo_pack(out, PARAMS_KEY_BITS / 8, w, PARAMS_NBAR * PARAMS_NBAR, PARAMS_EXTRACTED_BITS);
}