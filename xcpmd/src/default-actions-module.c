/*
 * default-actions-module.c
 *
 * XCPMD module that provides general-purpose actions.
 *
 * Copyright (c) 2015 Assured Information Security, Inc.
 *
 * Author:
 * Jennifer Temkin <temkinj@ainfosec.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "project.h"
#include "xcpmd.h"
#include "rules.h"


//Function prototypes
void do_nothing(struct arg_node * args);
void print_string(struct arg_node * args);
void log_string(struct arg_node * args);
void run_script(struct arg_node * args);


//Private data structures
struct action_table_row {
    char * name;
    void (* func)(struct arg_node *);
    char * prototype;
    char * pretty_prototype;
};


//Private data
static struct action_table_row action_table[] = {
    {"doNothing"   , do_nothing   , "n" , "void"                   } ,
    {"printString" , print_string , "s" , "string string_to_print" } ,
    {"logString"   , log_string   , "s" , "string string_to_log"   } ,
    {"runScript"   , run_script   , "s" , "string path_to_script"  }
};

static unsigned int num_action_types = sizeof(action_table) / sizeof(action_table[0]);


//Registers this module's action types.
//It is EXTREMELY important that constructors/destructors be static--otherwise,
//they may be shadowed by the constructors of previously loaded modules!
static void __attribute__ ((constructor)) init_module() {

    unsigned int i;

    for (i=0; i < num_action_types; ++i)
        add_action_type(action_table[i].name, action_table[i].func, action_table[i].prototype, action_table[i].pretty_prototype);
}


//Cleans up after this module.
static void __attribute__ ((destructor)) uninit_module() {
    return;
}


//Actions
void do_nothing(struct arg_node * args) {
    return;
}


void print_string(struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    char * string = node->arg.str;
    printf("%s\n", string);
}


void log_string(struct arg_node * args) {

    struct arg_node * node = get_arg(args, 0);
    char * string = node->arg.str;
    xcpmd_log(LOG_ALERT, "%s\n", string);
}


//This action requires some cooperation from SELinux--if xcpmd doesn't have
//sufficient privilege to run a particular script or command, this will fail.
void run_script(struct arg_node * args) {


    struct arg_node * node = get_arg(args, 0);
    char * command;

    //Automatically background the new process so we don't block on it.
    command = safe_sprintf("%s &", node->arg.str);

    if (system(command) == -1) {
        xcpmd_log(LOG_ERR, "%s failure running '%s'", __func__, command);
    }

    free(command);
}

