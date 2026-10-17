/* ML-KEM key encapsulation prototype (SYNTHETIC demo code). */
#include <oqs/oqs.h>

int main(void) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        return 1;
    }
    OQS_KEM_free(kem);
    return 0;
}
