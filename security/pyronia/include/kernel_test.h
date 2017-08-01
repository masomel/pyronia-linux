/** Provides utility functions and definitions for performing end-to-end
 * tests of the Pyronia LSM.
 *
 *@author Marcela S. Melara
 */

#ifndef __KERNEL_TEST_H
#define __KERNEL_TEST_H

#include "lib_policy.h"
#include "callgraph.h"
#include "audit.h"
#include "file.h"
#include "match.h"

static const char *test_libs[3];

static const char *test_names[2];

#ifndef NUM_DEFAULT
#define NUM_DEFAULT 2
#endif

static const char *default_names[NUM_DEFAULT];

static const char *test_prof = "/home/pyronia/kernel_permissions_checker_test";

static inline void init_testlibs(void) {
    test_libs[0] = "cam";
    test_libs[1] = "http";
    test_libs[2] = "img_processing";
}

static inline void init_testnames(void) {
    test_names[0] = "/tmp/cam0";
    test_names[1] = "127.0.0.1";
}

// these files should be allowed for all libs by default
static inline void init_default(void) {
    default_names[0] = "/lib/x86_64-linux-gnu/libc-2.23.so";
    default_names[1] = "/etc/ld.cache.so";
}

static inline int create_default_policy_entries(struct pyr_lib_policy_db *policy,
                                                const char *lib) {

    struct pyr_acl_entry *acl = NULL;
    int err = 0;

    int i;
    for (i = 0; i < NUM_DEFAULT; i++) {
        err = pyr_add_acl_entry(&acl, resource_entry, default_names[i], 1,
                            CAM_DATA);
        if (err) {
            return err;
        }

        // add a policy entry for lib to the permissions db
        err = pyr_add_lib_policy(&policy, lib, acl);
        if (err) {
            return err;
        }
    }

    return 0;
}

// Create a dummy Pyronia policy for a test process
// This policy will be tested when the appropriate LSM
// checks are triggered at runtime
static inline int init_lib_policy(struct pyr_lib_policy_db **policy) {
    int err = 0;
    struct pyr_lib_policy_db *db;
    struct pyr_acl_entry *acl;

    init_testlibs();
    init_testnames();
    init_default();

    // allocate the new policy db
    db = NULL;
    err = pyr_new_lib_policy_db(&db);
    if (err)
        goto fail;

    // create the ACL entry for "/tmp/cam0"
    acl = NULL;
    err = pyr_add_acl_entry(&acl, resource_entry, test_names[0], 1,
                            CAM_DATA);
    if (err) {
        goto fail;
    }

    // add a policy entry for "cam" to the permissions db
    err = pyr_add_lib_policy(&db, test_libs[0], acl);
    if (err) {
        goto fail;
    }

    // add the default policies for "cam"
    err = create_default_policy_entries(db, test_libs[0]);
    if (err) {
        goto fail;
    }

    // create the ACL entry for "127.0.0.1"
    acl = NULL;
    err = pyr_add_acl_entry(&acl, net_entry, test_names[1], OP_CONNECT,
                            CAM_DATA);
    if (err) {
        goto fail;
    }

    // add a policy entry for "http" to the permissions db
    err = pyr_add_lib_policy(&db, test_libs[1], acl);
    if (err) {
        goto fail;
    }

    // add the default policies for "http"
    err = create_default_policy_entries(db, test_libs[1]);
    if (err) {
        goto fail;
    }

    *policy = db;
    return 0;
 fail:
    pyr_free_lib_policy_db(&db);
    return err;
}

// Create a dummy callgraph with the given library for a test process
// This callgraph will be used to check the requested access/operation
// at runtime
static inline int init_callgraph(const char *lib, pyr_cg_node_t **cg) {
    int err = 0;

    pyr_cg_node_t *c = NULL;
    err = pyr_new_cg_node(&c, lib, CAM_DATA, NULL);
    if (err) {
        pyr_free_callgraph(&c);
        goto out;
    }

    *cg = c;
 out :
    return err;
}

// Set the file rule permissions given a policy DFA
static inline int set_file_perms(struct pyr_profile *profile) {

    unsigned int state;
    u32 perms;
    struct pyr_acl_entry *acl;
    struct pyr_lib_policy *policy;

    // set the permissions for the default files
    int i, j;
    for (i = 0; i < 2; i++){
        for (j = 0; j < NUM_DEFAULT; j++) {
            state = pyr_dfa_match(profile->file.dfa, profile->file.start, default_names[j]);

            perms = map_old_perms(dfa_user_allow(profile->file.dfa, state));
            perms |= PYR_MAY_META_READ;

            policy = pyr_find_lib_policy(profile->lib_perm_db, test_libs[i]);

            if (policy == NULL) {
                goto fail;
            }

            acl = pyr_find_lib_acl_entry(policy, default_names[j]);
            if (acl == NULL) {
                goto fail;
            }

            acl.target.fs_resource.perms = perms;
        }

        // set the permissions for the testname
        state = pyr_dfa_match(profile->file.dfa, profile->file.start,
                              test_names[0]);

        perms = map_old_perms(dfa_user_allow(profile->file.dfa, state));
        perms |= PYR_MAY_META_READ;

        policy = pyr_find_lib_policy(profile->lib_perm_db, test_libs[i]);

        if (policy == NULL) {
            goto fail;
        }

        acl = pyr_find_lib_acl_entry(policy, test_libs[0]);
        if (acl == NULL) {
            goto fail;
        }

        acl.target.fs_resource.perms = perms;
    }
    return 0;

 fail:
    return -1;
}

#endif
