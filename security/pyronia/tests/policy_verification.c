/** Tests the Pyronia library permissions
 * verification.
 *
 *@author Marcela S. Melara
 */

#include <stdio.h>
#include <string.h>

#include "tests.h"

// create a policy with all libraries
// and build a callgraph that results in allowed permissions
static int test_policy_verification_success(const char* libs[],
                                         const char* names[]) {
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

    pyr_cg_node_t *callgraph;
    // create a callgraph with only l3 -> l4
    // these are expected to have the same permissions
    err = test_callgraph_creation(libs+2, 2, &callgraph);

    if (err) {
        goto out;
    }

    uint32_t lib_perms;
    err = pyr_lib_cg_perms(db, callgraph, names[2], &lib_perms);
    if (err) {
        PYR_ERROR("pyr_lib_cg_perms returns %d\n", err);
        goto out;
    }

    // we should get permissions of 1 because both libraries in the
    // callgraph have permission to access `names[2]`
    if (lib_perms != 1) {
        err = 1;
        PYR_ERROR("Expecting effective permissions of 1, got %d\n",
                  lib_perms);
        goto out;
    }

 out:
    // make sure to free the memory
    pyr_free_lib_policy_db(&db);
    pyr_free_callgraph(&callgraph);
    return err;
}

static int test_policy_verification_fail(const char* libs[],
                                         const char* names[]) {
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

    pyr_cg_node_t *callgraph;
    err = test_callgraph_creation(libs, 4, &callgraph);

    if (err) {
        goto out;
    }

    uint32_t lib_perms;
    err = pyr_lib_cg_perms(db, callgraph, names[0], &lib_perms);
    if (err) {
        PYR_ERROR("pyr_lib_cg_perms returns %d\n", err);
        goto out;
    }

    // we should get permissions of 0 because each library in the
    // callgraph has permission to a distinct `names[i]`
    if (lib_perms != 0) {
        err = 1;
        PYR_ERROR("Expecting effective permissions of 0, got %d\n",
                  lib_perms);
        goto out;
    }

 out:
    // make sure to free the memory
    pyr_free_lib_policy_db(&db);
    pyr_free_callgraph(&callgraph);
    return err;
}

static int test_against_requested_perms_success(const char* libs[],
                                        const char* names[]) {
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

    pyr_cg_node_t *callgraph;
    // create a callgraph with only l3 -> l4
    // these are expected to have the same permissions
    err = test_callgraph_creation(libs+2, 2, &callgraph);

    if (err) {
        goto out;
    }

    uint32_t lib_perms;
    err = pyr_lib_cg_perms(db, callgraph, names[2], &lib_perms);
    if (err) {
        PYR_ERROR("pyr_lib_cg_perms returns %d\n", err);
        goto out;
    }

    // for the reasoning behind these tests, please see tests.h:
    // a bitwise AND of the requested permission and the negated
    // effective permissions should result in 0, which implies an
    // exact match in requested and the permissions

    // if requested permission is PERM1, we should get an allowed
    // operation because ~1 & 1 = 0
    if (PERM1 & ~lib_perms) {
        err = 1;
        PYR_ERROR("Expecting allowed with requested access of %d, and permissions %d\n",
                  PERM1, lib_perms);
        goto out;
    }

    // if requested permission is PERM2, we should get a disallowed
    // operation because ~1 & 2 = 2
    if (!(PERM2 & ~lib_perms)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM2);
        goto out;
    }

    // if requested permission is PERM3, we should get a disallowed
    // operation because ~1 & 3 = 2
    if (!(PERM3 & ~lib_perms)) {
        err = 1;
        PYR_ERROR("Expecting disallowed operation with requested access of %d\n",
                  PERM3);
        goto out;
    }

 out:
    // make sure to free the memory
    pyr_free_lib_policy_db(&db);
    pyr_free_callgraph(&callgraph);
    return err;
}

static int test_against_requested_perms_failed(const char* libs[],
                                        const char* names[]) {
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

    pyr_cg_node_t *callgraph;
    err = test_callgraph_creation(libs, 4, &callgraph);

    if (err) {
        goto out;
    }

    uint32_t lib_perms;
    err = pyr_lib_cg_perms(db, callgraph, names[0], &lib_perms);
    if (err) {
        PYR_ERROR("pyr_lib_cg_perms returns %d\n", err);
        goto out;
    }

    // for the reasoning behind these tests, please see tests.h:
    // a bitwise AND of the requested permission and the negated
    // effective permissions should result in 0, which implies an
    // exact match in requested and the permissions

    // if requested permission is PERM1, we should get a disallowed
    // operation because ~0 & 1 = 1
    if (!(PERM1 & ~lib_perms)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM1);
        goto out;
    }

    // if requested permission is PERM2, we should get a disallowed
    // operation because ~0 & 2 = 2
    if (!(PERM2 & ~lib_perms)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM2);
        goto out;
    }

    // if requested permission is PERM3, we should get a disallowed
    // operation because ~0 & 3 = 3
    if (!(PERM3 & ~lib_perms)) {
        err = 1;
        PYR_ERROR("Expecting disallowed with requested access of %d\n",
                  PERM3);
        goto out;
    }

 out:
    // make sure to free the memory
    pyr_free_lib_policy_db(&db);
    pyr_free_callgraph(&callgraph);
    return err;
}

int main(int argc, char *argv[]) {

    const char *libs[4];
    libs[0] = "l1";
    libs[1] = "l2";
    libs[2] = "l3";
    libs[3] = "l4";

    const char *names[4];
    names[0] = "/dev/cam0";
    names[1] = "/dev/cam0";
    names[2] = "/dev/cam1";
    names[3] = "/dev/cam1";

    int err = 0;
    int final_err = err;
    int passed = 0;
    PYR_DEBUG("Test successful policy verification... ");
    err = test_policy_verification_success(libs, names);
    if (err) {
        final_err = err;
        printf("\n");
    }
    else {
        passed++;
        printf("passed\n");
    }

    PYR_DEBUG("Test failed policy verification... ");
    err = test_policy_verification_fail(libs, names);
    if (err) {
        final_err = err;
        printf("\n");
    }
    else {
        passed++;
        printf("passed\n");
    }

    PYR_DEBUG("Test allowed access against requested permissions... ");
    err = test_against_requested_perms_success(libs, names);
    if (err) {
        final_err = err;
        printf("\n");
    }
    else {
        passed++;
        printf("passed\n");
    }

    PYR_DEBUG("Test failed access against requested permissions... ");
    err = test_against_requested_perms_failed(libs, names);
    if (err) {
        final_err = err;
        printf("\n");
    }
    else {
        passed++;
        printf("passed\n");
    }

    PYR_DEBUG("Passed %d/4 tests\n", passed);
    return final_err;
}
