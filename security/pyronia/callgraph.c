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

#include "include/callgraph.h"

#include "include/userland_test.h"

// Allocate a new callgraph node
int pyr_new_cg_node(pyr_cg_node_t **cg_root, const char* lib,
                        enum pyr_data_types data_type,
                        pyr_cg_node_t *child) {

    pyr_cg_node_t *n = (pyr_cg_node_t *)kvzalloc(sizeof(pyr_cg_node_t));

    if (n == NULL) {
        goto fail;
    }

    n->lib = lib;
    n->data_type = data_type;
    n->child = child;

    *cg_root = n;
    return 0;
 fail:
    kvfree(n);
    return -1;
}

// Gets the permissions for the given resource from the library's policy
static uint32_t get_perms_for_name(struct pyr_lib_policy * policy,
                              const char *name) {

    struct pyr_acl_entry *acl = pyr_find_lib_acl_entry(policy, name);

    // we don't have an entry in our ACL for this `name`,
    // so the library doesn't have any permissions to access `name`.
    // default-deny policy
    if (acl == NULL) {
        return 0;
    }

    return acl->perms;
}

// Traverse the given callgraph computing each module's permissions
// at each frame, and return the effective permission
int pyr_lib_cg_perms(struct pyr_lib_policy_db *lib_policy_db,
                     pyr_cg_node_t * callgraph, const char *name,
                     uint32_t *perms) {

    pyr_cg_node_t *cur_node = callgraph;
    int err = 0;
    uint32_t eff_perm = 0;
    struct pyr_lib_policy *cur_policy;

    // want effective permission to start as root library in callgraph
    cur_policy = pyr_find_lib_policy(lib_policy_db, cur_node->lib);

    // something seriously went wrong if we don't have the root lib
    // in our policy DB
    if (cur_policy == NULL) {
        // TODO: throw some big error here
        err = -1;
        goto out;
    }

    eff_perm = get_perms_for_name(cur_policy, name);

    // bail early since the root already doesn't have permission
    // to access name
    if (eff_perm == 0) {
        goto out;
    }

    cur_node = callgraph->child;
    while (cur_node != NULL) {
        cur_policy = pyr_find_lib_policy(lib_policy_db, cur_node->lib);

        // if we don't have an explicit policy for this library,
        // inherit the current effective permissions, otherwise adjust
        if (cur_policy != NULL) {
            // take the intersection of the permissions
            eff_perm &= get_perms_for_name(cur_policy, name);

            // bail early since the callgraph so far already doesn't have
            // access to `name`
            if (eff_perm == 0) {
                goto out;
            }
        }

        cur_node = cur_node->child;
    }

 out:
    *perms = eff_perm;
    return err;
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
