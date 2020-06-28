

#include <mach/mach.h>
#include <mach/task.h> // mach_task_self()
#include <stdio.h>
#include <stdlib.h>    // exit? 
#include  <unistd.h> // exit?


int main (int argc, char **argv)
{
    mach_port_t myPort = MACH_PORT_NULL;
    kern_return_t  kr = mach_port_allocate
                        (mach_task_self(), // WHERE? ipc_space_t task,
                         MACH_PORT_RIGHT_RECEIVE, // mach_port_right_t right,
                         &myPort); // mach_port_name_t *name
    if (KERN_SUCCESS != kr)
        {
            fprintf(stderr,"FUD! What does a guy have to do to get a port created?!\n");
            exit(1);
        }
    printf("Hoorah! Habemus Portum - 0x%x\n", myPort);
    printf("Incidentally, my self is 0x%x, and bootstrap is 0x%x\n",
           mach_task_self(),
           bootstrap_port);
    // Step II: Enumerate my port space (ipc_space_t)
    ipc_info_space_t space_info;
    ipc_info_name_array_t table_info;
    mach_msg_type_number_t table_infoCnt;
    ipc_info_tree_name_array_t tree_info;
    mach_msg_type_number_t tree_infoCnt;
    kr = mach_port_space_info (mach_task_self(), // ipc_space_inspect_t task,
                               &space_info, //ipc_info_space_t *space_info,
                               &table_info, // ipc_info_name_array_t *table_info,
                               &table_infoCnt, // mach_msg_type_number_t *table_infoCnt,
                               &tree_info, // ipc_info_tree_name_array_t *tree_info,
                               &tree_infoCnt); // mach_msg_type_number_t *tree_infoCnt
    if (KERN_SUCCESS != kr)
        {
            fprintf(stderr,"FUD!\n");
            exit(1);
        }
#if 0
    typedef struct ipc_info_name
    {
        mach_port_name_t iin_name;              /* port name, including gen number */
        /*boolean_t*/ integer_t iin_collision;   /* collision at this entry? */
        mach_port_type_t iin_type;      /* straight port type */
        mach_port_urefs_t iin_urefs;    /* user-references */
        natural_t iin_object;           /* object pointer/identifier */
        natural_t iin_next;             /* marequest/next in free list */
        natural_t iin_hash;             /* hash index */
    } ipc_info_name_t;
#endif
    int p;
    for (p = 0; p < table_infoCnt; p++)
        {
            printf("Port name: 0x%x, Type: 0x%x, Urefs: 0x%x, object: 0x%x\n",
                   table_info[p].iin_name,
                   table_info[p].iin_type,
                   table_info[p].iin_urefs,
                   table_info[p].iin_object);
        }
    return 0;
}


