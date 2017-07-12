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

// this is an individual entry in the ACL for
// a library
struct pyr_acl_entry {
    u32 perm;
    // the entry is either for a local resource
    // or a remote network destination
    union {
        struct path *resource;
        const char* net_dest;
    };
    enum pyr_data_types data_type;
    struct pyr_acl_entry next;
};

struct pyr_perm_db_entry {
  const char* lib;
  struct pyr_acl_entry acl;
};

#endif /* __PYR_LIBPOLICY_H */
