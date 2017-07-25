/*
 * Pyronia security module
 *
 * Implements the Pyronia library policy definitions.
 *
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#include <string.h>
#include "include/lib_policy.h"

#include "include/userland_test.h"

// Allocates a new ACL entry and adds it to the ACL pointed to by `acl`.
// This function can also be used to initialize `acl`.
// The new entry will be pointed to by `acl` when this function returns.
// Returns 0 on success, -1 on failure
int pyr_add_acl_entry(struct pyr_acl_entry **acl,
                      enum acl_entry_type entry_type,
                      const char *name, uint32_t perms,
                      enum pyr_data_types data_type) {
    struct pyr_acl_entry *new_entry =
        (struct pyr_acl_entry *)kvzalloc(sizeof(struct pyr_acl_entry));

    if (new_entry == NULL) {
        goto fail;
    }

    new_entry->entry_type = entry_type;
    switch(new_entry->entry_type) {
        case(resource_entry):
            new_entry->name.resource = name;
            break;
        case(net_entry):
            new_entry->name.net_dest = name;
            break;
        default:
            goto fail;
    }

    new_entry->perms = perms;
    new_entry->data_type = data_type;
    // insert at head of linked list
    new_entry->next = *acl;
    *acl = new_entry;

    return 0;
 fail:
    kvfree(new_entry);
    return -1;
}

// Allocates a new library policy and adds it to the policy DB pointed to
// by `policy_db`.
// This function can be used to initialize `policy_db`, but it *cannot* be
// used to allocate `policy_db`.
// The new policy will be pointed to by `policy_db->perm_db_head` when
// this function returns.
// Returns 0 on success, -1 on failure
int pyr_add_lib_policy(struct pyr_lib_policy_db **policy_db, const char *lib,
                      struct pyr_acl_entry *acl) {
    struct pyr_lib_policy *new_policy =
        (struct pyr_lib_policy *)kvzalloc(sizeof(struct pyr_lib_policy));

    if (new_policy == NULL) {
        goto fail;
    }

    new_policy->lib = lib;
    new_policy->acl = acl;

    // insert at head of linked list
    new_policy->next = (*policy_db)->perm_db_head;
    (*policy_db)->perm_db_head = new_policy;

    return 0;
 fail:
    kvfree(new_policy);
    return -1;

}

// Allocates a new policy DB
// Returns 0 on success, -1 on failure
int pyr_new_lib_policy_db(struct pyr_lib_policy_db **policy_db) {
    struct pyr_lib_policy_db *db =
        (struct pyr_lib_policy_db *)kvzalloc(sizeof(struct pyr_lib_policy_db));

    if (db == NULL) {
        goto fail;
    }

    db->perm_db_head = NULL;

 fail:
    kvfree(db);
    return -1;
}

// Finds the ACL entry for `name` in the lib policy given by `policy`.
// Returns null if no entry for `name` exists.
struct pyr_acl_entry * pyr_find_lib_acl_entry(struct pyr_lib_policy *policy,
                                              const char *name) {

    // traverse the ACL entry linked list, start at the head
    struct pyr_acl_entry *runner = policy->acl;

    while (runner != NULL) {
        // we have two types of entries, so need to check the type
        // on each before we determine if we've found the requested ACL entry
        switch (runner->entry_type) {
        case(resource_entry):
            if (!strncmp(runner->name.resource, name, strlen(name))) {
                return runner;
            }
            break;
        case(net_entry):
            if (!strncmp(runner->name.net_dest, name, strlen(name))) {
                return runner;
            }
            break;
        default:
            // FIXME: set errno here or something
            return NULL;
        }

        runner = runner->next;
    }

    // if we get here, we don't have an ACL entry for this name
    // (resource or net destination)
    return NULL;
}

// Finds the lib policy for `lib` in the policy DB given by `policy_db`.
// Returns null if no entry for `lib` exists.
struct pyr_lib_policy * pyr_find_lib_policy(struct pyr_lib_policy_db *policy_db, const char *lib) {

    // traverse the policy linked list, start at the head
    struct pyr_lib_policy *runner = policy_db->perm_db_head;

    while (runner != NULL) {
        if (!strncmp(runner->lib, lib, strlen(lib))) {
            return runner;
        }
        runner = runner->next;
    }

    // if we get here, we don't have a policy for this library
    return NULL;
}

// Recursively free the ACL entries
static void free_acl_entry(struct pyr_acl_entry **entry) {
    struct pyr_acl_entry *e = *entry;

    if (e->next == NULL) {
        switch (e->entry_type) {
        case(resource_entry):
            e->name.resource = NULL;
            break;
        case(net_entry):
            e->name.net_dest = NULL;
            break;
        default:
            // FIXME: set errno here or something
            break;
        }
        kvfree(e);
    }
    else {
        free_acl_entry(&(e->next));
    }
    *entry = NULL;
}

// Recursively free the lib policies
static void free_lib_policy(struct pyr_lib_policy **policy) {
    struct pyr_lib_policy *p = *policy;

    if (p->next == NULL) {
        p->lib = NULL;
        free_acl_entry(&(p->acl));
        kvfree(p);
    }
    else {
        free_lib_policy(&(p->next));
    }
    *policy = NULL;
}

// Free a lib policy DB
// Recursively frees all lib policies and their ACL entries
void pyr_free_lib_policy_db(struct pyr_lib_policy_db **policy_db) {
    struct pyr_lib_policy_db *db = *policy_db;
    free_lib_policy(&(db->perm_db_head));
    *policy_db = NULL;
}
