/*
 * Pyronia security module
 *
 * Implements the Pyronia callgraph interface.
 *
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include "include/pyronia.h"
#include "include/callgraph.h"

// Allocate a new callgraph node
int pyr_new_cg_node(pyr_cg_node_t **cg_root, const char* lib, enum pyr_data_types data_type) {
    pyr_cg_node_t *n = (pyr_cg_node_t *)kvzalloc(sizeof(pyr_cg_node_t));

    if (n == NULL) {
        goto fail;
    }

    n->lib = lib;
    n->data_type = data_type;
    n->child = NULL;

    *cg_root = n;
    return 0;
 fail:
    kvfree(n);
    return -1;
}

// Recursively free the callgraph nodes
static void free_node(pyr_cg_node_t **node) {
    pyr_cg_node_t *n = *node;

    if (n->child == NULL) {
        n->lib = NULL;
        kvfree(n);
    }
    else {
        free_node(&(n->child));
    }
    *node = NULL;
}

// Free a callgraph
void pyr_free_callgraph(pyr_cg_node_t **cg_root) {
    free_node(cg_root);
}
