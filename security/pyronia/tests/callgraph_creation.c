/** Tests the Pyronia library permissions
 * verification.
 *
 *@author Marcela S. Melara
 */

#include <stdio.h>
#include <string.h>

#include "../include/callgraph.h"

#include "../include/userland_test.h"

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

int main(int argc, char *argv[]) {

    const char *libs[4];
    libs[0] = "l1";
    libs[1] = "l2";
    libs[2] = "l3";
    libs[3] = "l4";

    pyr_cg_node_t *callgraph;
    int err;

    err = test_callgraph_creation(libs, 4, &callgraph);
    if (err) {
        PYR_ERROR("pyr_new_cg_node returned %d\n", err);
        return err;
    }

    pyr_cg_node_t *runner = callgraph;
    int i = 3;
    while(runner != NULL || i > 0) {
        if (strncmp(runner->lib, libs[i], strlen(libs[i]))) {
            PYR_ERROR("Expected %s, got %s\n", libs[i], runner->lib);
            return -1;
        }
        i--;
        runner = runner->child;
    }

    // make sure to free the memory
    pyr_free_callgraph(&callgraph);

    return 0;
}
