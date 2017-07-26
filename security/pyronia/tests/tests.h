/** Provides utility functions used for testing the Pyronia LSM in userland.
 *
 *@author Marcela S. Melara
 */

#include "../include/lib_policy.h"
#include "../include/callgraph.h"
#include "../include/userland_test.h"

// represents different potential requested permissions
// Only PERM1 & PERM1 are compatible because, following the same logic
// as the profile-level verification in places like pyr_path_perm,
// an operation should only be allowed if the exact same access
// is requests
// PERM1 & PERM2 and PERM1 & PERM3 result in a 0-permissions, i.e.
// disallowed operation
#define PERM1 1
#define PERM2 2
#define PERM3 3

static int test_acl_creation(const char *name, struct pyr_acl_entry **acl) {

    struct pyr_acl_entry *a = NULL;
    int i, err;

    err = pyr_add_acl_entry(&a, resource_entry, name, PERM1,
                                CAM_DATA);
    if (err) {
        return err;
    }

    *acl = a;
    return 0;
}

static int test_lib_policy_creation(const char *libs[], int len,
                                    const char *names[],
                                    struct pyr_lib_policy_db **policy) {

    int i, err;
    for (i = 0; i < len; i++) {
        struct pyr_acl_entry *acl = NULL;

        err = test_acl_creation(names[i%len], &acl);
        if (err) {
            PYR_ERROR("pyr_add_acl_entry returned %d\n", err);
            return err;
        }

        err = pyr_add_lib_policy(policy, libs[i], acl);
        if (err) {
            PYR_ERROR("pyr_add_lib_policy returned %d\n", err);
            return err;
        }
    }

    return 0;
}

static int test_callgraph_creation(const char *libs[], int len,
                                   pyr_cg_node_t **cg) {

    pyr_cg_node_t *child = NULL;
    int i, err;
    for (i = 0; i < len; i++) {
        pyr_cg_node_t *next;

        err = pyr_new_cg_node(&next, libs[i], CAM_DATA, child);
        if (err) {
            return err;
        }

        child = next;
    }

    *cg = child;
    return 0;
}
