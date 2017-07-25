/*
 * Pyronia security module
 *
 * This file contains Pyronia library policy definitions.
 *
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_LIBPOLICY_H
#define __PYR_LIBPOLICY_H

#include <stdint.h>
#include <stdio.h>

/** pyr_data_types defines the possible expected sensitive
 * data types obtained from sensors or files
 */
enum pyr_data_types {
    CAM_DATA,
    MIC_DATA,
    ENV_DATA,
    MISC_FILE_DATA,
    // TODO: add more fine-grained types
};

/* pyr_lib_perms defines the possible permissions a library can
 * have under Pyronia
 */
enum pyr_lib_perms {
    CAM_PERM, // read-only access to the camera
    MIC_PERM, // read-only access to the microphone
    ENV_SENSOR_PERM, // read-only access to a specified environmental sensor
    CRED_PERM, // read-only access to specified credentials
    FILE_R_PERM, // read access from a specified file
    FILE_W_PERM, // write access to a specified file
    NET_R_PERM, // read access from a specified net addr
    // write access of a specified data type to a specified net addr
    NET_W_PERM,
    EXEC_PERM, //exec access of a specified binary
};

struct path;

// indicates whether a library ACL entry
// is for a local resource
// or a remote network destination
enum acl_entry_type {
    resource_entry,
    net_entry,
};

// this is an individual entry in the ACL for
// a library
struct pyr_acl_entry {

    enum acl_entry_type entry_type;

    union {
        const char *resource;
        const char *net_dest;
    } name;

    uint32_t perms;
    enum pyr_data_types data_type;
    struct pyr_acl_entry *next;
};

/* An individual library policy for an application.
 * lib: the library this policy belongs too
 * acl: the ACL containing the library's permissions
 * next: the next entry in the library policy database
 */
struct pyr_lib_policy {
    const char* lib;
    struct pyr_acl_entry *acl;
    struct pyr_lib_policy *next;
};

/* An application's Pyronia library policy database.
 * policy_db_head: The first entry in the policy database
 *      linked list
 */
struct pyr_lib_policy_db {
    struct pyr_lib_policy *perm_db_head;
    // TODO: What other metadata do we need here?
};

int pyr_add_acl_entry(struct pyr_acl_entry **, enum acl_entry_type,
                      const char *, uint32_t, enum pyr_data_types);
int pyr_add_lib_policy(struct pyr_lib_policy_db **, const char *,
                       struct pyr_acl_entry *);
int pyr_new_lib_policy_db(struct pyr_lib_policy_db **);
struct pyr_acl_entry * pyr_find_lib_acl_entry(struct pyr_lib_policy *,
                                              const char *);
struct pyr_lib_policy * pyr_find_lib_policy(struct pyr_lib_policy_db *,
                                            const char *);
void pyr_free_lib_policy_db(struct pyr_lib_policy_db **);

#endif /* __PYR_LIBPOLICY_H */
