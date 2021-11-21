//
// Created by ghost on 21/11/2021.
//

#ifndef ZMAP_PROBE_MODULE_LIST_H
#define ZMAP_PROBE_MODULE_LIST_H

probe_module_t *MODULE_TCP_SYNSCAN();
probe_module_t *MODULE_TCP_SYNACKSCAN();
probe_module_t *MODULE_ICMP_ECHO();
probe_module_t *MODULE_ICMP_ECHO_TIME();
probe_module_t *MODULE_UDP();
probe_module_t *MODULE_NTP();
probe_module_t *MODULE_UPNP();
probe_module_t *MODULE_DNS();
probe_module_t *MODULE_BACNET();

#endif //ZMAP_PROBE_MODULE_LIST_H
