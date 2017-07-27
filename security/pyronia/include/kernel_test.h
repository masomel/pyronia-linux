/** Provides utility functions and definitions for performing end-to-end
 * tests of the Pyronia LSM.
 *
 *@author Marcela S. Melara
 */

#include "lib_policy.h"
#include "callgraph.h"

static const char *test_libs[3];

static const char *test_names[2];

static void init_testlibs() {
    test_libs[0] = "cam";
    test_libs[1] = "http";
    test_libs[2] = "img_processing";
}

static void init_testnames() {
    test_names[0] = "/tmp/cam0";
    test_names[1] = "127.0.0.1";
}

// Create a dummy Pyronia policy for a test process
// This policy will be tested when the appropriate LSM
// checks are triggered at runtime
static int init_lib_policy(struct pyr_lib_policy_db **policy) {
    int err = 0;

    // allocate the new policy db
    struct pyr_lib_policy_db *db = NULL;
    err = pyr_new_lib_policy_db(&db);
    if (err)
        goto fail;

    // create the ACL entry for "/tmp/cam0"
    struct pyr_acl_entry *acl = NULL;
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

    // create the ACL entry for "127.0.0.1"
    err = pyr_add_acl_entry(&acl, net_entry, test_names[1], 1,
                            CAM_DATA);
    if (err) {
        goto fail;
    }

    // add a policy entry for "http" to the permissions db
    err = pyr_add_lib_policy(&db, test_libs[1], acl);
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
static int init_callgraph(const char *lib, pyr_cg_node_t **cg) {
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
