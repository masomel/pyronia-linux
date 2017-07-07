/*
 * Pyronia security module
 *
 * This file contains Pyronia permissions database definitions.
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

struct path;
// FIXME: implement data types that correspond to the output of a device
// read and are tracked b/w libs to ensure their dispatch to the specified
// network destination
struct data_type;

struct pyr_acl_entry {
  enum pyr_lib_cap cap;
  struct path resource;
  struct data_type data_type;
  const char* destination;
  struct pyr_acl_entry next;
};

struct pyr_perm_db_entry {
  const char* lib;
  struct pyr_acl_entry acl;
};
  
#endif /* __PYR_PERMDB_H */
