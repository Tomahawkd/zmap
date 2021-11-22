//
// Created by ghost on 21/11/2021.
//

#include "api/modules.h"
#include "module_test.h"
#include "module_isatap.h"

INIT_FUNCTION() {
	probe_module_t *array[2] = {
		MODULE_TCP_SYN(), MODULE_ISATAP()
	};
	add_probe_modules(array, 2);
}

DEINIT_FUNCTION() {

}
