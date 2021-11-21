//
// Created by ghost on 21/11/2021.
//

#include "api/modules.h"
#include "module_test.h"

INIT_FUNCTION() {
	probe_module_t *tcp_syn = MODULE_TCP_SYN();
	add_probe_modules(&tcp_syn, 1);
}

DEINIT_FUNCTION() {

}
