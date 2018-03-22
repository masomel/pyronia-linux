/*
 * Pyronia security module
 *
 * This file contains the Pyronia callgraph definitions.
 *
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_CALLGRAPH_H
#define __PYR_CALLGRAPH_H

#include <uapi/linux/pyronia_mac.h>
#include "lib_policy.h"

int pyr_new_cg_node(pyr_cg_node_t **, const char *, enum pyr_data_types,
                    pyr_cg_node_t *);
void pyr_free_callgraph(pyr_cg_node_t **);
int pyr_compute_lib_perms(struct pyr_lib_policy_db *, pyr_cg_node_t *,
                     const char *, u32 *);

#endif /* __PYR_CALLGRAPH_H */
