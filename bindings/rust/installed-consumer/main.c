#include <duct.h>
#include <duct_noise.h>

int main(void) {
    duct_engine_cfg_t cfg = {.io_threads = 1u, .workers = 1u};
    return (cfg.io_threads == 1u && duct_noise_vtbl() != nullptr) ? 0 : 1;
}
