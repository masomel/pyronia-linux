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

#ifndef __PYR_PERMDB_H
#define __PYR_PERMDB_H

#include "capability.h"

/* pyr_lib_perms - defines the possible permissions a library can
 * have under Pyronia
 */
enum pyr_lib_perms {
  CAM_PERM, // read-only access to the camera
  MIC_PERM, // read-only access to the microphone
  SENSOR_PERM, // read-only access to a specified sensor
  CRED_PERM, // read-only access to specified credentials
  FILE_R_PERM, // read access from a specified file
  FILE_W_PERM, // write access to a specified file
  NET_R_PERM, // read access from a specified net addr
  NET_W_PERM, // write access of a specified data type to a specified net addr
  EXEC_PERM, //exec access of a specified binary
};

struct path;
// FIXME: implement data types that correspond to the output of a device
// read and are tracked b/w libs to ensure their dispatch to the specified
// network destination
struct data_type;

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
    struct data_type data_type;
    struct pyr_acl_entry next;
};

struct pyr_perm_db_entry {
  const char* lib;
  struct pyr_acl_entry acl;
};

#endif /* __PYR_PERMDB_H */
