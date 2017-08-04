/********************************************************************************************
* Frodo: a post-quantum key exchange based on the Learning with Errors (LWE) problem.
*
* Abstract: matrix arithmetic functions required by the kex scheme
*********************************************************************************************/

//#define AES128_ECB

#if defined(AES128_ECB)
    #include "aes/aes.h"
#else
#if !defined(USE_AVX2)
    #include "sha3/fips202.h"
#else
    #include "sha3/fips202x4.h"
#endif
#endif    
#if defined(USE_AVX2)
    #include <immintrin.h>
#endif


int MACRIFY(oqs_kex_lwe_frodo_mul_add_as_plus_e_on_the_fly)(uint16_t *out, const uint16_t *s, const uint16_t *e, struct oqs_kex_lwe_frodo_params *params) 
{ // Generate-and-multiply: generate matrix A (N x N) row-wise, multiply by s on the right.
  // Inputs: s, e (N x N_BAR)
  // Output: out = A*s + e (N x N_BAR)
    int i, j, k;
    ALIGN_HEADER(32) int16_t a_row[4*PARAMS_N] ALIGN_FOOTER(32) = {0};

    for (i = 0; i < (PARAMS_N*PARAMS_NBAR); i += 2) {    
        *((uint32_t*)&out[i]) = *((uint32_t*)&e[i]);
    }    
    
#if defined(AES128_ECB)
    int16_t a_row_temp[4*PARAMS_N] = {0};                       // Take four lines of A at once

    assert(params->seed_len == 16);
    void *aes_key_schedule = NULL;
    OQS_AES128_load_schedule(params->seed, &aes_key_schedule, 1);    
                                     
    for (j = 0; j < PARAMS_N; j += PARAMS_STRIPE_STEP) {
        a_row_temp[j + 1 + 0*PARAMS_N] = j;                     // Loading values in the little-endian order
        a_row_temp[j + 1 + 1*PARAMS_N] = j;
        a_row_temp[j + 1 + 2*PARAMS_N] = j;
        a_row_temp[j + 1 + 3*PARAMS_N] = j;
    }

    for (i = 0; i < PARAMS_N; i += 4) {
        for (j = 0; j < PARAMS_N; j += PARAMS_STRIPE_STEP) {    // Go through A, four rows at a time
            a_row_temp[j + 0*PARAMS_N] = i+0;                   // Loading values in the little-endian order                                
            a_row_temp[j + 1*PARAMS_N] = i+1;
            a_row_temp[j + 2*PARAMS_N] = i+2;
            a_row_temp[j + 3*PARAMS_N] = i+3;
        }

        OQS_AES128_ECB_enc_sch((uint8_t*)a_row_temp, 4*PARAMS_N*sizeof(int16_t), aes_key_schedule, (uint8_t*)a_row);
#else       
#if !defined(USE_AVX2)
    for (i = 0; i < PARAMS_N; i += 4) {
        cshake128_simple((unsigned char*)(a_row + 0*PARAMS_N), (unsigned long long)(2*PARAMS_N), (uint16_t)(i+0), params->seed, (unsigned long long)params->seed_len);
        cshake128_simple((unsigned char*)(a_row + 1*PARAMS_N), (unsigned long long)(2*PARAMS_N), (uint16_t)(i+1), params->seed, (unsigned long long)params->seed_len);
        cshake128_simple((unsigned char*)(a_row + 2*PARAMS_N), (unsigned long long)(2*PARAMS_N), (uint16_t)(i+2), params->seed, (unsigned long long)params->seed_len);
        cshake128_simple((unsigned char*)(a_row + 3*PARAMS_N), (unsigned long long)(2*PARAMS_N), (uint16_t)(i+3), params->seed, (unsigned long long)params->seed_len);
#else
    for (i = 0; i < PARAMS_N; i += 4) {
        cshake128_simple4x((unsigned char*)(a_row), (unsigned char*)(a_row + PARAMS_N), (unsigned char*)(a_row + 2*PARAMS_N), (unsigned char*)(a_row + 3*PARAMS_N), 
                           (unsigned long long)(2*PARAMS_N), (uint16_t)(i), (uint16_t)(i+1), (uint16_t)(i+2), (uint16_t)(i+3), params->seed, (unsigned long long)params->seed_len);
#endif
#endif

#if !defined(WINDOWS) | (defined(WINDOWS) & !defined(USE_AVX2)) 
        for (k = 0; k < PARAMS_NBAR; k++) {
            uint16_t sum[4] = {0};
            for (j = 0; j < PARAMS_N; j++) {                    // Matrix-vector multiplication            
                uint16_t sp = s[k*PARAMS_N + j];
                sum[0] += a_row[0*PARAMS_N + j] * sp;           // Go through four lines with same s
                sum[1] += a_row[1*PARAMS_N + j] * sp;
                sum[2] += a_row[2*PARAMS_N + j] * sp;
                sum[3] += a_row[3*PARAMS_N + j] * sp;
            }
            out[(i+0)*PARAMS_NBAR + k] += sum[0];
            out[(i+2)*PARAMS_NBAR + k] += sum[2];
            out[(i+1)*PARAMS_NBAR + k] += sum[1];
            out[(i+3)*PARAMS_NBAR + k] += sum[3];
        }
#else  // Using vector intrinsics, fixed for N = 752 
        for (k = 0; k < PARAMS_NBAR; k++) {                           
            ALIGN_HEADER(32) uint32_t sum0[8], sum1[8], sum2[8], sum3[8] ALIGN_FOOTER(32);
            __m256i a0, a1, a2, a3, b, acc0, acc1, acc2, acc3;

            acc0 = _mm256_setzero_si256();
            acc1 = _mm256_setzero_si256();
            acc2 = _mm256_setzero_si256();
            acc3 = _mm256_setzero_si256();
            b = _mm256_setzero_si256();
            for (j = 0; j < PARAMS_N; j += 16) {                // Matrix-vector multiplication
                b = _mm256_load_si256((__m256i*)&s[k*PARAMS_N + j]);

                a0 = _mm256_load_si256((__m256i*)&a_row[(0*PARAMS_N) + j]);                               
                a0 = _mm256_madd_epi16(a0, b);
                acc0 = _mm256_add_epi32(a0, acc0);
        
                a1 = _mm256_load_si256((__m256i*)&a_row[(1*PARAMS_N) + j]);                               
                a1 = _mm256_madd_epi16(a1, b);
                acc1 = _mm256_add_epi32(a1, acc1);
        
                a2 = _mm256_load_si256((__m256i*)&a_row[(2*PARAMS_N) + j]);                               
                a2 = _mm256_madd_epi16(a2, b);
                acc2 = _mm256_add_epi32(a2, acc2);
        
                a3 = _mm256_load_si256((__m256i*)&a_row[(3*PARAMS_N) + j]);                              
                a3 = _mm256_madd_epi16(a3, b);
                acc3 = _mm256_add_epi32(a3, acc3);
            }

            _mm256_store_si256((__m256i*)sum0, acc0);
            out[(i+0)*PARAMS_NBAR + k] += sum0[0] + sum0[1] + sum0[2] + sum0[3] + sum0[4] + sum0[5] + sum0[6] + sum0[7];
            //out[(i+0)*PARAMS_NBAR + k] = (uint32_t)(out[(i+0)*PARAMS_NBAR + k] << 17) >> 17;    // Fixed to params->q = 1 << 15
            _mm256_store_si256((__m256i*)sum1, acc1);
            out[(i+1)*PARAMS_NBAR + k] += sum1[0] + sum1[1] + sum1[2] + sum1[3] + sum1[4] + sum1[5] + sum1[6] + sum1[7];
            //out[(i+1)*PARAMS_NBAR + k] = (uint32_t)(out[(i+1)*PARAMS_NBAR + k] << 17) >> 17;    
            _mm256_store_si256((__m256i*)sum2, acc2);
            out[(i+2)*PARAMS_NBAR + k] += sum2[0] + sum2[1] + sum2[2] + sum2[3] + sum2[4] + sum2[5] + sum2[6] + sum2[7];
            //out[(i+2)*PARAMS_NBAR + k] = (uint32_t)(out[(i+2)*PARAMS_NBAR + k] << 17) >> 17;    
            _mm256_store_si256((__m256i*)sum3, acc3);
            out[(i+3)*PARAMS_NBAR + k] += sum3[0] + sum3[1] + sum3[2] + sum3[3] + sum3[4] + sum3[5] + sum3[6] + sum3[7];
            //out[(i+3)*PARAMS_NBAR + k] = (uint32_t)(out[(i+3)*PARAMS_NBAR + k] << 17) >> 17; 
        } 
#endif
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
    int i, j, k, kk, t = 0;

    for (i = 0; i < (PARAMS_N*PARAMS_NBAR); i += 2) {
        *((uint32_t*)&out[i]) = *((uint32_t*)&e[i]);
    }

#if defined(AES128_ECB)
    uint16_t a_cols[PARAMS_N*PARAMS_STRIPE_STEP] = {0};
    ALIGN_HEADER(32) uint16_t a_cols_t[PARAMS_N*PARAMS_STRIPE_STEP] ALIGN_FOOTER(32) = {0};
    uint16_t a_cols_temp[PARAMS_N*PARAMS_STRIPE_STEP] = {0};

    assert(params->seed_len == 16);
    void *aes_key_schedule = NULL;
    OQS_AES128_load_schedule(params->seed, &aes_key_schedule, 1);

    for (i = 0, j = 0; i < PARAMS_N; i++, j += PARAMS_STRIPE_STEP) {
        a_cols_temp[j] = i;                                     // Loading values in the little-endian order
    }

    for (kk = 0; kk < PARAMS_N; kk += PARAMS_STRIPE_STEP) {     // Go through A's columns, 8 (== PARAMS_STRIPE_STEP) columns at a time.       
        for (i = 0; i < (PARAMS_N*PARAMS_STRIPE_STEP); i += PARAMS_STRIPE_STEP) {
            a_cols_temp[i + 1] = kk;                            // Loading values in the little-endian order
        }

        OQS_AES128_ECB_enc_sch((uint8_t*)a_cols_temp, PARAMS_N*PARAMS_STRIPE_STEP*sizeof(int16_t), aes_key_schedule, (uint8_t*)a_cols);

        for (i = 0; i < PARAMS_N; i++) {                        // Transpose a_cols to have access to it in the column-major order.
            for (k = 0; k < PARAMS_STRIPE_STEP; k++) {
                a_cols_t[k*PARAMS_N + i] = a_cols[i*PARAMS_STRIPE_STEP + k];
            }
        }        

#if !defined(USE_AVX2)
        for (i = 0; i < PARAMS_NBAR; i++) {
            for (k = 0; k < PARAMS_STRIPE_STEP; k += PARAMS_PARALLEL) {
                uint16_t sum[PARAMS_PARALLEL] = {0};
                for (j = 0; j < PARAMS_N; j++) {                // Matrix-vector multiplication
                    uint16_t sp = s[i*PARAMS_N + j];
                    //for (kp = 0; kp < PARAMS_PARALLEL; kp++)
                    //    sum[kp] += sp * a_cols_t[(k+kp)*PARAMS_N + j];
                    sum[0] += sp * a_cols_t[(k+0)*PARAMS_N + j];
                    sum[1] += sp * a_cols_t[(k+1)*PARAMS_N + j];
                    sum[2] += sp * a_cols_t[(k+2)*PARAMS_N + j];
                    sum[3] += sp * a_cols_t[(k+3)*PARAMS_N + j];
                }
                out[i*PARAMS_N + kk + k + 0] += sum[0];
                out[i*PARAMS_N + kk + k + 2] += sum[2];
                out[i*PARAMS_N + kk + k + 1] += sum[1];
                out[i*PARAMS_N + kk + k + 3] += sum[3];
            }
        }
    }
#else  // Using vector intrinsics, fixed for N = 752 
        for (i = 0; i < PARAMS_NBAR; i++) {
            for (k = 0; k < PARAMS_STRIPE_STEP; k += PARAMS_PARALLEL) {
                ALIGN_HEADER(32) uint32_t sum[8 * PARAMS_PARALLEL] ALIGN_FOOTER(32);
                __m256i a[PARAMS_PARALLEL], b, acc[PARAMS_PARALLEL];
                //for (kp = 0; kp < PARAMS_PARALLEL; kp++)
                //    acc[kp] = _mm256_setzero_si256();
                acc[0] = _mm256_setzero_si256();
                acc[1] = _mm256_setzero_si256();
                acc[2] = _mm256_setzero_si256();
                acc[3] = _mm256_setzero_si256();
                for (j = 0; j < PARAMS_N; j += 16) {            // Matrix-vector multiplication
                    b = _mm256_load_si256((__m256i*)&s[i*PARAMS_N + j]);

                    //for (kp = 0; kp < PARAMS_PARALLEL; kp++) {
                    //    a[kp] = _mm256_load_si256((__m256i*)&a_cols_t[(k + kp)*PARAMS_N + j]);
                    //    a[kp] = _mm256_madd_epi16(a[kp], b);
                    //    acc[kp] = _mm256_add_epi16(a[kp], acc[kp]);
                    //}
                    a[0] = _mm256_load_si256((__m256i*)&a_cols_t[(k+0)*PARAMS_N + j]);
                    a[0] = _mm256_madd_epi16(a[0], b);
                    acc[0] = _mm256_add_epi16(a[0], acc[0]);
                    a[1] = _mm256_load_si256((__m256i*)&a_cols_t[(k+1)*PARAMS_N + j]);
                    a[1] = _mm256_madd_epi16(a[1], b);
                    acc[1] = _mm256_add_epi16(a[1], acc[1]);
                    a[2] = _mm256_load_si256((__m256i*)&a_cols_t[(k+2)*PARAMS_N + j]);
                    a[2] = _mm256_madd_epi16(a[2], b);
                    acc[2] = _mm256_add_epi16(a[2], acc[2]);
                    a[3] = _mm256_load_si256((__m256i*)&a_cols_t[(k+3)*PARAMS_N + j]);
                    a[3] = _mm256_madd_epi16(a[3], b);
                    acc[3] = _mm256_add_epi16(a[3], acc[3]);
                }

                _mm256_store_si256((__m256i*)(sum + (8*0)), acc[0]);
                out[i*PARAMS_N + kk + k + 0] += sum[8*0 + 0] + sum[8*0 + 1] + sum[8*0 + 2] + sum[8*0 + 3] + sum[8*0 + 4] + sum[8*0 + 5] + sum[8*0 + 6] + sum[8*0 + 7];
                //out[i * PARAMS_N + kk + k + 0] = (uint32_t)(out[i*PARAMS_N + kk + k + 0] << 17) >> 17;    // Fixed to params->q = 1 << 15)
                _mm256_store_si256((__m256i*)(sum + (8*1)), acc[1]);
                out[i*PARAMS_N + kk + k + 1] += sum[8*1 + 0] + sum[8*1 + 1] + sum[8*1 + 2] + sum[8*1 + 3] + sum[8*1 + 4] + sum[8*1 + 5] + sum[8*1 + 6] + sum[8*1 + 7];
                //out[i * PARAMS_N + kk + k + 1] = (uint32_t)(out[i*PARAMS_N + kk + k + 1] << 17) >> 17;
                _mm256_store_si256((__m256i*)(sum + (8*2)), acc[2]);
                out[i*PARAMS_N + kk + k + 2] += sum[8*2 + 0] + sum[8*2 + 1] + sum[8*2 + 2] + sum[8*2 + 3] + sum[8*2 + 4] + sum[8*2 + 5] + sum[8*2 + 6] + sum[8*2 + 7];
                //out[i * PARAMS_N + kk + k + 2] = (uint32_t)(out[i*PARAMS_N + kk + k + 2] << 17) >> 17;
                _mm256_store_si256((__m256i*)(sum + (8*3)), acc[3]);
                out[i*PARAMS_N + kk + k + 3] += sum[8*3 + 0] + sum[8*3 + 1] + sum[8*3 + 2] + sum[8*3 + 3] + sum[8*3 + 4] + sum[8*3 + 5] + sum[8*3 + 6] + sum[8*3 + 7];
                //out[i * PARAMS_N + kk + k + 3] = (uint32_t)(out[i*PARAMS_N + kk + k + 3] << 17) >> 17;
            }
        }
    }
#endif
    OQS_AES128_free_schedule(aes_key_schedule);

#else  // cSHAKE128

    ALIGN_HEADER(32) uint16_t a_cols[4*PARAMS_N] ALIGN_FOOTER(32) = {0};

#if !defined(USE_AVX2)
    for (kk = 0; kk < PARAMS_N; kk+=4) {
        cshake128_simple((unsigned char*)(a_cols + 0*PARAMS_N), (unsigned long long)(2*PARAMS_N), (uint16_t)(kk+0), params->seed, (unsigned long long)params->seed_len);
        cshake128_simple((unsigned char*)(a_cols + 1*PARAMS_N), (unsigned long long)(2*PARAMS_N), (uint16_t)(kk+1), params->seed, (unsigned long long)params->seed_len);
        cshake128_simple((unsigned char*)(a_cols + 2*PARAMS_N), (unsigned long long)(2*PARAMS_N), (uint16_t)(kk+2), params->seed, (unsigned long long)params->seed_len);
        cshake128_simple((unsigned char*)(a_cols + 3*PARAMS_N), (unsigned long long)(2*PARAMS_N), (uint16_t)(kk+3), params->seed, (unsigned long long)params->seed_len);

        for (i = 0; i < PARAMS_NBAR; i++) {
            uint16_t sum[PARAMS_N] = {0};
            for (j = 0; j < 4; j++) {
                uint16_t sp = s[i*PARAMS_N + kk + j];
                for (k = 0; k < PARAMS_N; k++) {                // Matrix-vector multiplication
                    sum[k] += sp * a_cols[(t+j)*PARAMS_N + k];
                }
             } 
            for(k = 0; k < PARAMS_N; k++){
                out[i*PARAMS_N + k] += sum[k];
            }
        }
    }
#else  // Using vector intrinsics, fixed for N = 752
    for (kk = 0; kk < PARAMS_N; kk+=4) {
        cshake128_simple4x((unsigned char*)(a_cols), (unsigned char*)(a_cols + PARAMS_N), (unsigned char*)(a_cols + 2*PARAMS_N), (unsigned char*)(a_cols + 3*PARAMS_N), 
                           (unsigned long long)(2*PARAMS_N), (uint16_t)(kk), (uint16_t)(kk+1), (uint16_t)(kk+2), (uint16_t)(kk+3), params->seed, (unsigned long long)params->seed_len);

        for (i = 0; i < PARAMS_NBAR; i++) {
            __m256i a, b0, b1, b2, b3, acc[PARAMS_N/16];
            b0 = _mm256_set1_epi16(s[i*PARAMS_N + kk + 0]);       
            b1 = _mm256_set1_epi16(s[i*PARAMS_N + kk + 1]);        
            b2 = _mm256_set1_epi16(s[i*PARAMS_N + kk + 2]);        
            b3 = _mm256_set1_epi16(s[i*PARAMS_N + kk + 3]);
            for (j = 0; j < PARAMS_N; j+=16) {                  // Matrix-vector multiplication
                acc[j/16] = _mm256_load_si256((__m256i*)&out[i*PARAMS_N + j]);
                a = _mm256_load_si256((__m256i*)&a_cols[(t+0)*PARAMS_N + j]);
                a = _mm256_mullo_epi16(a, b0);
                acc[j/16] = _mm256_add_epi16(a, acc[j/16]);
                a = _mm256_load_si256((__m256i*)&a_cols[(t+1)*PARAMS_N + j]);
                a = _mm256_mullo_epi16(a, b1);
                acc[j/16] = _mm256_add_epi16(a, acc[j/16]);
                a = _mm256_load_si256((__m256i*)&a_cols[(t+2)*PARAMS_N + j]);
                a = _mm256_mullo_epi16(a, b2);
                acc[j/16] = _mm256_add_epi16(a, acc[j/16]);
                a = _mm256_load_si256((__m256i*)&a_cols[(t+3)*PARAMS_N + j]);
                a = _mm256_mullo_epi16(a, b3);
                acc[j/16] = _mm256_add_epi16(a, acc[j/16]);
            }

            for (j = 0; j < PARAMS_N/16; j++) {
                _mm256_store_si256((__m256i*)&out[i*PARAMS_N + 16*j], acc[j]);
            }
        }
    }
#endif
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
                out[i * PARAMS_NBAR + j] += b[i * PARAMS_N + k] * s[j * PARAMS_N + k];
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