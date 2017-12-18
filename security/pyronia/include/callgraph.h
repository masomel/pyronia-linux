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

#include "lib_policy.h"

// pyr_cg_node represents a single node in a callgraoh used
// by the Pyronia LSM to determine if a library has permission
// to complete a sensitive operation
struct pyr_cg_node {
    const char *lib;
    enum pyr_data_types data_type; // defined in lib_policy.h
    // only keep a downward link to the child since we compute the
    // effective permission by traversing from the main app to the function
    // triggering the security check
    struct pyr_cg_node *child;
};

typedef struct pyr_cg_node pyr_cg_node_t;

int pyr_new_cg_node(pyr_cg_node_t **, const char *, enum pyr_data_types,
                    pyr_cg_node_t *);
void pyr_free_callgraph(pyr_cg_node_t **);
int pyr_compute_lib_perms(struct pyr_lib_policy_db *, pyr_cg_node_t *,
                     const char *, u32 *);

#endif /* __PYR_CALLGRAPH_H */
