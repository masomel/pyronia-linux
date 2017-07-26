/** Tests the Pyronia library permissions
 * verification.
 *
 *@author Marcela S. Melara
 */

#include <stdio.h>
#include <string.h>

#include "../include/lib_policy.h"

#include "../include/userland_test.h"

static int test_acl_creation(const char *name, struct pyr_acl_entry **acl) {

    struct pyr_acl_entry *a = NULL;
    int i, err;

    err = pyr_add_acl_entry(&a, resource_entry, name, 1,
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

int main(int argc, char *argv[]) {

    const char *libs[4];
    libs[0] = "l1";
    libs[1] = "l2";
    libs[2] = "l3";
    libs[3] = "l4";

    const char *names[4];
    names[0] = "/dev/cam0";
    names[1] = "/dev/cam1";
    names[2] = "/dev/cam2";
    names[3] = "/dev/cam3";

    struct pyr_acl_entry *acl;
    int err = 0;

    struct pyr_lib_policy_db *db;
    err = pyr_new_lib_policy_db(&db);
    if (err) {
        PYR_ERROR("pyr_new_lib_policy_db returns %d\n", err);
        goto out;
    }

    err = test_lib_policy_creation(libs, 4, names, &db);
    if (err) {
        goto out;
    }

    int i;
    for (i = 0; i < 4; i++) {
        struct pyr_lib_policy *p;
        struct pyr_acl_entry *a;

        p = pyr_find_lib_policy(db, libs[i]);

        if (p == NULL) {
            PYR_ERROR("Expected policy for %s, none found\n", libs[i]);
            err = 1;
            goto out;
        }

        a = pyr_find_lib_acl_entry(p, names[i%4]);
        if (a == NULL) {
            PYR_ERROR("Expected ACL entry for %s, none found\n", names[i%4]);
            err = 1;
            goto out;
        }
    }

 out:
    // make sure to free the memory
    pyr_free_lib_policy_db(&db);
    return err;
}
