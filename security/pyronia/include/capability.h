/*
 * Pyronia security module
 *
 * This file contains Pyronia capability mediation definitions.
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2013 Canonical Ltd.
 * Copyright (C) 2017 Princeton University
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 */

#ifndef __PYR_CAPABILITY_H
#define __PYR_CAPABILITY_H

#include <linux/sched.h>

#include "pyroniafs.h"

struct pyr_profile;

/* pyr_proc_caps - confinement data for capabilities
 * @allowed: capabilities mask
 * @audit: caps that are to be audited
 * @quiet: caps that should not be audited
 * @kill: caps that when requested will result in the task being killed
 * @extended: caps that are subject finer grained mediation
 */
struct pyr_proc_caps {
	kernel_cap_t allow;
	kernel_cap_t audit;
	kernel_cap_t quiet;
	kernel_cap_t kill;
	kernel_cap_t extended;
};

/* pyr_lib_caps - defines the possible capabilities a library can
 * have in Pyronia
 */
enum pyr_lib_caps {
  CAM_CAP, // read-only access to the camera
  MIC_CAP, // read-only access to the microphone
  SENSOR_CAP, // read-only access to a specified sensor
  CRED_CAP, // read-only access to specified credentials
  FILE_R_CAP, // read access from a specified file
  FILE_W_CAP, // write access to a specified file
  NET_R_CAP, // read access from a specified net addr
  NET_W_CAP, // write access of a specified data type to a specified net addr
  EXEC_CAP, //exec access of a specified binary
};

extern struct pyr_fs_entry pyr_fs_entry_caps[];

int pyr_proc_capable(struct pyr_profile *profile, int cap, int audit);

static inline void pyr_free_cap_rules(struct pyr_proc_caps *caps)
{
	/* NOP */
}

#endif /* __PYR_CAPBILITY_H */
