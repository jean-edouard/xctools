/*
 * parser.c
 *
 * Provide high-level interface for loading modules and policy.
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

/* Reasons you would want to hack on this file:
   - You need to change the parser's behavior : see @@STATE_MACHINE@@
   - You need to add a new data type : see @@DATA_TYPE_MANAGEMENT@@
   - You need to fix a bug : good luck
*/

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "project.h"
#include "xcpmd.h"
#include "rules.h"
#include "db-helper.h"
#include "parser.h"
#include "prototypes.h"

// @@DATA_TYPE_MANAGEMENT@@ - Add new types below, and assign an aribrary index
// initialize_parse_data() needs to know about your type possibly (if it is a
// meta-target and will result in parsing that transitions to another target).
// If not reusing the current state machine, another must be built
// If adding an fn arg type, the action_acceptArg function must be changed
// each arg type here gets handled in a case/switch
// Types enum, optimized for storage
typedef unsigned char PARSED_TYPE;
typedef const unsigned char CONST_PARSED_TYPE;
#define TYPE_UNDETERMINED     ((CONST_PARSED_TYPE)0)
#define TYPE_INT              ((CONST_PARSED_TYPE)1)
#define TYPE_FLOAT            ((CONST_PARSED_TYPE)2)
#define TYPE_STR              ((CONST_PARSED_TYPE)3)
#define TYPE_BOOL             ((CONST_PARSED_TYPE)4)
#define TYPE_VAR              ((CONST_PARSED_TYPE)5)
#define TYPE_ACTION           ((CONST_PARSED_TYPE)50)
#define TYPE_CONDITION        ((CONST_PARSED_TYPE)51)
#define TYPE_UNDO_ACTION      ((CONST_PARSED_TYPE)52)
#define TYPE_VAR_MAP          ((CONST_PARSED_TYPE)90)
#define TYPE_RULE             ((CONST_PARSED_TYPE)91)
#define TYPE_ARG              ((CONST_PARSED_TYPE)92)

//#define DBGOUT(...) printf(__VA_ARGS__)
//#define ERROUT(...) printf(__VA_ARGS__)

#define DBGOUT(...) xcpmd_log(LOG_DEBUG, __VA_ARGS__)
#define ERROUT(...) xcpmd_log(LOG_ERR, __VA_ARGS__)


//Recoverable (and possibly coincident) parse errors
#define BAD_CONDITION       0x010
#define BAD_ACTION          0x020
#define BAD_UNDO            0x040

//Masks to obtain the pieces of an error.
#define RULE_ERROR_MASK     0x00F
#define RECOVERABLE_MASK    0x0F0
#define PARSE_ERROR_MASK    0xF00


/* A little policy intro is in order. Don't take this too seriously, it should
   just serve as a crash course. Grammar (BNF) currently is as follows:

   POLICY ::= RULES
   RULES ::= RULES RULE
         | RULE
   RULE ::= IDENTIFIER CONDITIONS ACTIONS UNDOACTIONS
   IDENTIFIER ::= <string>
   CONDITIONS ::= CFUNCTIONLIST "\0"
   ACTIONS ::= AFUNCTIONS "\0"
           | "\0"
   UNDOACTIONS ::= AFUNCTIONLIST "\0"
               | "\0"
   CFUNCTIONLIST ::= CFUNCTIONLIST " " CFUNCTIONITEM
                 | CFUNCTIONITEM
   AFUNCTIONLIST ::= AFUNCTIONLIST " " AFUNCTIONITEM
                 | AFUNCTIONITEM
   CFUNCTIONITEM ::= INVERTER CFUNCTION
   AFUNCTIONITEM ::= INVERTER AFUNCTION
   CFUNCTION ::= FUNCTION
   AFUNCTION ::= FUNCTION
   INVERTER ::= "!"
            | ""
   FUNCTION ::= <string> "(" ARGLIST ")"
   ARGLIST ::= ARGLIST " " ARG
           | ARG
   ARG ::= "\"" <string> "\""
       | <integer>
       | <float>
       | <boolean>
       | "$" <string>


   And, so here is where things break down a bit:

   First - there is no one right way to write rules, as long as xcpmd
   knows which functions are conditions, which are actions, and which are
   undoactions. So, currently we allow policy in the db such that a rule's
   conditions, actions, and undoactions are called out by keys under each
   rule. The db also will utilize namespaces for each rule so that there
   are not collisions between identifiers that are inserted from different
   sources. Namespaces are a required construct within the dom-store which is
   folded into a rule's identifier to prevent conflict, but ultimately, the
   namespace + identifier pair reduce to just being an identifier. Namespaces
   may not be implemented just yet.

   We also allow adding policy via the DBUS - remmeber, it doesn't matter how
   it gets in there, as long as its uniquely identified and broken down by
   CONDITIONS, ACTIONS, and UNDOACTIONS.


   Second - later policy takes priority over earlier policy.


   Third - The names for CFUNCTIONs and AFUNCTIONs are seen directly within
   the xcpmd sources in the action tables and map to C functions that are
   either boolean functions that evaluate a condition (thus a CFUNCTION) or a
   void function which performs an action (AFUNCTION). While the syntax for
   CFUNCTIONs and AFUNCTIONs are identical, they cannot be intermixed and the
   namespaces for valid function names are unique, this is why we call them
   out in the grammar even though there is no syntactic difference.
*/

//Used to internally represent arbitrarily typed values for function arguments
union fn_arg_val {
    signed long as_int; //integer values
    float as_float; //floating point values
    char * as_str; //string values - this gets freed automagically if .as_str != NULL
    bool as_bool; //boolean values
};


//Forward declarations, see below for explanations
struct fn;
struct fn_arg;
struct var_map;
struct parse_data;
struct parse_state;
struct state_transition;
struct state_list;


//Code representation of a FUNCTIONITEM/FUNCTIONLIST from the grammar
struct fn {
    char * name; //Function identifier
    struct fn_arg * args; //Code representation of argument list to function
    bool undo; //Presense or absense of inverter in policy ("!" prefix)
    struct fn * next; //Forward link to next function to form a function list
};

//Code representation of an ARG/ARGLIST from the grammar
struct fn_arg {
    union fn_arg_val val; //Typed version of a function argument value from policy
    PARSED_TYPE type; //Data type of the value in .val
    struct fn_arg * next; //Forward link to the next argument in an argument list
};

//Keeps a track of variable name->value mapping - don't be mislead by them
//being treated as functions, functions are easily parsable by the existing
//parser and innately can be used to map names to values by structuring the
//input as "name(value)" and having the parser do all the lifting. We abstract
//away all the weirdness in how we store variables with helper functions.
struct var_map {
    struct fn * vars_as_fns; //List of functions used to store variables where
                             //the function names are the variable names, and
                             //the sole argument for each function is always a
                             //string and corresponds to the variable's value
    struct fn * vars_as_fns_tail; //Tracks last entry in the above list
};

//A global-esque data structure that tracks parse data until it is finally
//handed off to the policy engine itself.
struct parse_data {
    char * rule_name; //Rule identifier, used to uniquely identify it
    struct parse_state * state; //Current state the parser state machine is in
    struct parse_state * start_state; //Starting state for parser state machine
    bool undo; //True if inverter symbol was encountered in current parse unit
    bool finished; //Signals the parse should conclude
    int error_code; //Error category
    int rule_error_code; //Specific rule-related error codes

    char * var_map_str; //Input string for parser that contains "variable(value)" formatted, space separated entries
    char * conditions_str; //Input string for parser that contains a space separated list of conditions
    char * actions_str;  //Input string for parser that contains a space separated list of actions
    char * undo_actions_str; //Input string for parser that contains a space separated list of undo actions
    PARSED_TYPE subject_type; //Identifies the type of the overall data being parsed (e.g. a rule vs variables) - used chiefly to set the first .parsing value
    PARSED_TYPE parsing; //Identifies the type currently being parsed (e.g. actions portion of a rule)
    PARSED_TYPE arg_type; //Identifies the type of the current argument being pased within the current parse unit

    char * parse_str; //Identifies the current input string for the parser that is actively being parsed upon - same as .parse_str_start
    char * parse_str_start; //Identifies the start of the current input string - consider for removal, replace with .parse_str
    char * parse_str_end; //Identifies the end of the current input string
    char * parse_ptr; //Identifies the location in the parse_str that is currently being parsed

    unsigned long accum_sz; //The allocated size of the accumulators (each are equal to this size)
    char * accum_name; //A string which holds a function name as it is being accumulated
    char * name_ptr; //Identifies the location in accum_name that is currently being written to
    char * accum_arg; //A string which holds an unconverted argument as it is being accumulated in string form
    char * arg_ptr; //Identifies the location in accum_arg that is currently being written to

    struct var_map * var_map; //Contans (with some indirection and storage caveats) a mapping of variable names through values
    struct fn_arg * args; //Head node of a linked list of arguments that are in a post-parse format
    struct fn_arg * args_tail; //Tail node of the argument linked list
    struct fn * conditions; //Head node of a linked list of condition functions that are in a post-parse format
    struct fn * conditions_tail; //Tail node of the condition linked list
    struct fn * actions; //Head node of a linked list of action functions to use upon rule activation that are in a post-parse format
    struct fn * actions_tail; //Tail node of the actions activation linked list
    struct fn * undo_actions; //Head node of a linked list of action functions to use upon rule deactivation (undo actions) that are in a post-parse format
    struct fn * undo_actions_tail; //Tail node of the action dectivation (undo actions) linked list
    struct fn * parsed_arg; //Single node containing a parsed argument. Used when parsing TYPE_ARG.

    char * message; //Holds messages to be output for error reporting
};

//Describes a state in the parsing state machine
struct parse_state {
    char * name;    //Used to identify the state for debug output purposes
    struct state_transition * transitions; //Linked list of transitions (aka "edges") to the state
    void (* error_action)(struct parse_data *, char); //Fall-through action to perform if no transitions are able to be taken
};

//Describes edges for each state in the parsing state machine
struct state_transition {
    bool (* condition)(char); //If the result of this function with the current character being parsed is true, then this transition is "taken"
    void (* action)(struct parse_data *, char); //This is executed when this transition is "taken"
    struct parse_state *destination; //This is the next state that is set when this transition is "taken"
    struct state_transition *next; //Next transition in a list of state edges
};

//Allows a list of states to be kept, useful for tracking all states without traversing state machine, allowing for teardown/cleanup
// !!! MUST BE initialized with init_state_list() !!!
struct state_list {
    struct parse_state * state; //An arbitrary state to be stored in this node of the list
    struct state_list * next; //Pointer to next node of the list
};


//Creates and returns an arg_node struct and populates it with the argument type and value from a given fn_arg struct
struct arg_node conv_fn_arg(struct fn_arg fnarg) {

    struct arg_node arg;

    switch(fnarg.type) {
        case TYPE_INT:
            arg.type = ARG_INT;
            arg.arg.i = fnarg.val.as_int;
            break;
        case TYPE_FLOAT:
            arg.type = ARG_FLOAT;
            arg.arg.f = fnarg.val.as_float;
            break;
        case TYPE_STR:
            arg.type = ARG_STR;
            arg.arg.str = fnarg.val.as_str;
            break;
        case TYPE_BOOL:
            arg.type = ARG_BOOL;
            arg.arg.b = fnarg.val.as_bool;
            break;
        case TYPE_VAR:
            arg.type = ARG_VAR;
            arg.arg.var_name = fnarg.val.as_str;
            break;
        default:
            arg.type = ARG_NONE;
            arg.arg.i = 0;
    }

    return arg;
}


//Used to combine more than one error into a single error message
void error_append(struct parse_data * data, //Current parse_data struct, this function will append into data->message
                  char * format, //Printf style format string to append
                  ...) //Any arguments to that printf string
{

    va_list args;
    va_start(args, format);
    safe_str_append(&data->message, format, args);
    va_end(args);
}

//Bottleneck function for all generic error logging/output
//Allocates a buffer for data->message and sprintf()s a message into it.
void error(struct parse_data * data, //parse_data that is in use at the time
           char * format,   //Printf style format string
           ...) //Any arguments to that printf string
{

    int length;
    char * string;
    va_list args;

    if (data->message != NULL) {
        free(data->message);
        data->message = NULL;
    }

    va_start(args, format);
    length = vsnprintf(NULL, 0, format, args) + 1;
    va_end(args);
    string = (char *)malloc(length * sizeof(char));
    va_start(args, format);
    vsnprintf(string, length, format, args);
    va_end(args);

    data->message = string;
}

//Handles the formatting of output in the event of a parse error
void parse_error(struct parse_data * data, //parse_data that is in use at the time
                 char * s, //String describing what was expected
                 char c) //Character that was actually sent to the parser
{

    switch (c) {
        case '\0':
            error(data, "expected %s, got '\\0' (ASCII %d)", s, (unsigned char)(c));
            break;
        case '\n':
            error(data, "expected %s, got '\\n' (ASCII %d)", s, (unsigned char)(c));
            break;
        case '\t':
           error(data, "expected %s, got '\\t' (ASCII %d)", s, (unsigned char)(c));
           break;
        case '\r':
           error(data, "expected %s, got '\\r' (ASCII %d)", s, (unsigned char)(c));
           break;
        default:
            if (c < ' ' || c > '~') {
                error(data, "expected %s, got ASCII %d", s, (unsigned char)(c));
            }
            else {
                error(data, "expected %s, got '%c' (ASCII %d)", s, c, (unsigned char)(c));
            }
    }
}

//DEBUGGING FN: Prints an argument from a fn_arg struct
void output_fn_arg(struct fn_arg * arg) {
    if (!arg) {
        return;
    }
    switch (arg->type) {
    case TYPE_INT:
        DBGOUT("> INT ARG: %ld\n", arg->val.as_int);
        break;
    case TYPE_FLOAT:
        DBGOUT("> FLOAT ARG: %f\n", arg->val.as_float);
        break;
    case TYPE_STR:
        DBGOUT("> STR ARG: %s\n", arg->val.as_str);
        break;
    case TYPE_BOOL:
        if (arg->val.as_bool == false) {
            DBGOUT("> BOOL ARG: false\n");
        }
        else {
            DBGOUT("> BOOL ARG: true\n");
        }
        break;
    default:
        DBGOUT("> INVALID ARG\n");
        break;
    }
}

//DEBUGGING FN: Prints an fn struct and calls output_fn_arg on every fn_arg structs to print them too
void output_fn(struct fn * fn) {
    struct fn_arg * arg;

    if (!fn) {
        return;
    }

    if (fn->name) {
        if (fn->undo) {
            DBGOUT(">> FN NAME: %s\n", fn->name);
        }
        else {
            DBGOUT(">> !FN NAME: %s\n", fn->name);
        }
    }
    else {
        DBGOUT(">> UNNAMED FNS\n");
    }
    arg = fn->args;
    while (arg != NULL) {
        output_fn_arg(arg);
        arg = arg->next;
    }
}

//DEBUGGING FN: Calls output_fn on each fn struct in a list of fn structs and thereby prints each fn struct and all of its fn_arg structs
void output_fns(struct fn * fns) {
    while (fns) {
        output_fn(fns);
        fns = fns->next;
    }
}

//DEBUGGING FN: Prints a rule by printing its name and calling output_fns on the conditions, actions, and undo actions for a given rule
void output_rule(char * name, struct fn * conditions, struct fn * actions, struct fn * undo_actions) {
    if (name) {
        DBGOUT(">>>> RULE: %s\n", name);
    }
    else {
        DBGOUT(">>>> UNNAMED RULE\n");
    }
    DBGOUT(">>> CONDITIONS\n");
    output_fns(conditions);
    DBGOUT(">>> ACTIONS\n");
    output_fns(actions);
    DBGOUT(">>> UNDO ACTIONS\n");
    output_fns(undo_actions);
}

//Initializes a state_list struct. Memory management of the state_list itself is the responsibility of the caller.
// !!! MEMORY ALLOCATED BY HELPER FUNCTIONS !!!
// !!! MUST CALL free_state_list() on a pointer to this data structure !!!
void init_state_list(struct state_list * state_list) {
    state_list->state = NULL;
    state_list->next = NULL;
}

//Initializes a var_map struct. Memory management of the var_map itself is the responsibility of the caller.
// !!! MEMORY ALLOCATED BY HELPER FUNCTIONS !!!
// !!! MUST CALL free_var_map() on a pointer to this data structure !!!
void init_var_map(struct var_map * var_map) {
    var_map->vars_as_fns = NULL;
    var_map->vars_as_fns_tail = NULL;
}

//Walks a var_map struct to look up a particular value by name and returns it and its type in the output parameters
//Returns: true if the search succeeded, false otherwise
bool get_var_from_map(struct var_map * var_map, //var_map struct to search
                      char * name, //variable name
                      union fn_arg_val * OUT_val, //variable value
                      PARSED_TYPE * OUT_type) //variable type
{
    struct fn * f;

    for (f = var_map->vars_as_fns ; f != NULL ; f = f->next) {
        if (0 == strcmp(name, f->name)) {
            switch(f->args->type) {
            case TYPE_INT:
                OUT_val->as_int = f->args->val.as_int;
                break;
            case TYPE_FLOAT:
                OUT_val->as_float = f->args->val.as_float;
                break;
            case TYPE_STR:
                OUT_val->as_str = f->args->val.as_str;
                break;
            case TYPE_BOOL:
                OUT_val->as_bool = f->args->val.as_bool;
                break;
            default:
                return false;
            }
            (*OUT_type) = f->args->type;
            return true;
        }
    }
    return false;
}

//TODO: Double check this function, had a weird merge here that showed no real diffs
// Allocates and initializes a new fn struct with provided data
// !!! ALLOCATES MEMORY !!!
// !!! MUST CALL pop_and_free_fn() OR free_fns() to deallocate !!!
struct fn * new_fn(struct fn * last, //Last fn struct in the desired fn list to append this to, NULL if this is a single or head node
                   char * name, //function name, reference does not need to remain valid after call
                   struct fn_arg * args, //any arguments to this function in the form of an fn_arg struct (which may link to other fn_args), NULL if no arguments
                   bool undo) // true if the function is inverted by presence of the "!" character prior
{
    struct fn * f;
    if (name == NULL) {
        return NULL;
    }

    f = malloc(sizeof(struct fn));
    f->name = strdup(name);
    f->args = args;
    f->undo = undo;
    f->next = NULL;
    if (last != NULL) {
        last->next = f;
    }
    return f;
}

// Allocates and initializes a new fn_arg struct with provided data
// !!! ALLOCATES MEMORY !!!
// !!! MUST CALL pop_and_free_arg() OR call an appropriate freeing function on the owning fn struct !!!
struct fn_arg * new_fn_arg(struct fn_arg * last, union fn_arg_val val, PARSED_TYPE type) {
    struct fn_arg * arg;

    arg = malloc(sizeof(struct fn_arg));
    arg->val = val;
    arg->type = type;
    arg->next = NULL;
    if (last != NULL) {
        last->next = arg;
    }
    return arg;
}

//Frees the head of an fn_arg struct list and returns the head of the remaining list or NULL if the list is now empty
struct fn_arg * pop_and_free_arg(struct fn_arg * arg) {
    struct fn_arg * next;

    if (arg == NULL) {
        return NULL;
    }

    next = arg->next;
    if ((arg->type == TYPE_STR || arg->type == TYPE_VAR) && (arg->val.as_str != NULL)) {
        free(arg->val.as_str);
        arg->val.as_str = NULL;
    }
    free(arg);
    return next;
}

//!!! Private API !!!
//Bottom half of the add_to_var_map and add_to_var_map_as_arg functions - does the creation/adding of the fn struct to the fn struct list in the var_map struct
bool __add_to_var_map_internal(struct var_map * var_map, //var_map struct to add var/value pairs to
                               char * name, //variable name
                               struct fn_arg * arg) //value as an fn_arg struct
{
    struct fn * fn;

    fn = new_fn(var_map->vars_as_fns_tail, name, arg, false);
    if (fn == NULL) {
        return false;
    }
    if (var_map->vars_as_fns == NULL) {
        var_map->vars_as_fns = fn;
    }
    var_map->vars_as_fns_tail = fn;
    return true;
}

//Adds a variable/value pair to a var_map struct with the value already in fn_arg form and adds it to the fn struct list in a var_map struct
bool add_to_var_map_as_arg(struct var_map * var_map, //var_map struct to add var/value pairs to
                           char * name, //variable name
                           struct fn_arg * arg, //value as an fn_arg struct
                           char ** error) //output location to catch any errors (usually data->message) //TODO: Right?
{
    struct arg_node node;
    union fn_arg_val UNUSED_val;
    PARSED_TYPE UNUSED_type;
    if (name == NULL) {
        return FSM_ERROR;
    }

    if (get_var_from_map(var_map, name, &UNUSED_val, &UNUSED_type)) {
        return OVERLAPPING_VARS; //new name is already in var map
    }
    else {
        node = conv_fn_arg(*arg);
        if (add_var(name, node.type, node.arg, error) == NULL) {
            return INVALID_VAR_TYPE; //couldn't be added; probably a type mismatch
        }
    }

    if (!__add_to_var_map_internal(var_map, name, arg)) {
        return MEMORY_ERROR;
    }
    else {
        return NO_PARSE_ERROR;
    }
}

//Adds a variable/value pair to a var_map struct by converting the value/type given into an fn_arg struct and adding it to the fn struct list in a var_map struct
bool add_to_var_map(struct var_map * var_map, //var_map struct to add var/value pairs to
                    char * name, //variable name
                    union fn_arg_val val, //value as an fn_arg struct
                    PARSED_TYPE type) //type of value that val is
{
    union fn_arg_val UNUSED_val;
    PARSED_TYPE UNUSED_type;

    if (name == NULL) {
        return false;
    }

    if (get_var_from_map(var_map, name, &UNUSED_val, &UNUSED_type)) {
        return false; //new name is already in var map
    }

    return __add_to_var_map_internal(var_map, name, new_fn_arg(NULL, val, type));
}

//Removes the head fn struct from a list of fn structs and frees it and all of its associated fn_arg structs
//Returns the remainder of the list or NULL if this was the last/only item
struct fn * pop_and_free_fn(struct fn * f) {
    struct fn * next;
    if (f == NULL) {
        return NULL;
    }

    next = f->next;
    free(f->name);
    f->name = NULL;
    while (f->args != NULL) {
        f->args = pop_and_free_arg(f->args);
    }
    free(f);
    return next;
}

//Frees an fn struct or a list of fn structs and all of their associated fn_arg structs
void free_fns(struct fn * f) {
    while (f != NULL) {
        f = pop_and_free_fn(f);
    }
}

//Frees a var_map struct
void free_var_map(struct var_map * var_map) {
    free_fns(var_map->vars_as_fns);
    var_map->vars_as_fns = NULL;
    var_map->vars_as_fns_tail = NULL;
}

//Frees a parse_data struct and all associated data in it that would not otherwise be freed
void cleanup_parse_data(struct parse_data * data) {
    struct fn_arg * arg;

    if (data->message != NULL) {
        free(data->message);
        data->message = NULL;
    }
    if (data->accum_name != NULL) {
        free(data->accum_name);
        data->accum_name = NULL;
    }
    if (data->accum_arg != NULL) {
        free(data->accum_arg);
        data->accum_arg = NULL;
    }

    data->accum_sz = 0;
    data->accum_name = NULL;
    data->name_ptr = NULL;
    data->accum_arg = NULL;
    data->arg_ptr = NULL;

    //These should always be NULL as they end up consumed by rules engine
    arg = data->args;
    while (arg != NULL) {
        arg = pop_and_free_arg(arg);
    }
    free_fns(data->conditions);
    free_fns(data->actions);
    free_fns(data->undo_actions);
    free_fns(data->parsed_arg);

    data->args = NULL;
    data->args_tail = NULL;
    data->conditions = NULL;
    data->conditions_tail = NULL;
    data->actions = NULL;
    data->actions_tail = NULL;
    data->undo_actions = NULL;
    data->undo_actions_tail = NULL;
    data->parsed_arg = NULL;
}

// !!! MEMORY MAY BE ALLOCATED BY HELPER FUNCTIONS !!!
// !!! MUST CALL cleanup_parse_data() WHEN ALL FINISHED WITH THIS REUSABLE STRUCT !!!
// !!! DOES NOT COPY STRINGS !!!
// Cleanup also occurs in this function
//Used to initialize an allocated parse_data struct
void init_parse_data(struct parse_data * data, //the parse_data struct being initialized
                     struct var_map * var_map, //an already initialized var_map struct that is intended for use to store variable name->value mappings
                     struct parse_state * start, //the initial state to begin from within the parsing state machine
                     char * rule_name, //the name of the rule being parsed (NULL if parse target is not a rule)
                     char * var_map_str, //a string containing variable mappings in a space separated name(value) format (NULL if parse target is not a var_map)
                     char * conditions_str, //a string containing a rule's conditions (NULL if parse target is not a rule)
                     char * actions_str, //a string containing a rule's actions (NULL if parse target is not a rule, or if rule has no actions)
                     char * undo_actions_str, //a string containing a rule's undo actions (NULL if parse target is not a rule, or if rule has no undo actions)
                     PARSED_TYPE subject_type) //the type of the parse target, used to govern state machine
{

    data->rule_name = rule_name;
    data->state = data->start_state = start;
    data->undo = true;
    data->finished = false;
    data->error_code = NO_PARSE_ERROR;
    data->rule_error_code = RULE_CODE_NOT_SET;

    data->var_map_str = var_map_str;
    data->conditions_str = conditions_str;
    data->actions_str = actions_str;
    data->undo_actions_str = undo_actions_str;
    data->subject_type = subject_type;
    switch (data->subject_type) {
    case TYPE_RULE:
        data->parsing = TYPE_CONDITION;
        break;
    default:
        data->parsing = data->subject_type;
        break;
    }
    data->arg_type = TYPE_UNDETERMINED;

    data->parse_str = NULL;
    data->parse_str_start = NULL;
    data->parse_str_end = NULL;
    data->parse_ptr = NULL;

    data->var_map = var_map;

    //The below clears out all the active parsing information and it should only happen when a parse_data struct is first being intialized
    if (!(rule_name || var_map_str || actions_str || conditions_str || undo_actions_str || (subject_type != TYPE_UNDETERMINED))) {
        data->accum_sz = 0;
        data->accum_name = NULL;
        data->name_ptr = NULL;
        data->accum_arg = NULL;
        data->arg_ptr = NULL;
        data->args = NULL;
        data->args_tail = NULL;
        data->conditions = NULL;
        data->conditions_tail = NULL;
        data->actions = NULL;
        data->actions_tail = NULL;
        data->undo_actions = NULL;
        data->undo_actions_tail = NULL;
        data->parsed_arg = NULL;
        data->message = NULL;
    }

    cleanup_parse_data(data);
}

//Sets up the next character in the parse string to be parsed
void adv_parse_ptr(struct parse_data * data) {
    if (data && data->parse_ptr) {
        (data->parse_ptr)++; //FIXME: Should ensure we are within bounds when advancing
    }
}

//Rewinds to the previous character in the parse string
void rew_parse_ptr(struct parse_data * data) {
    if (data && data->parse_ptr) {
        (data->parse_ptr)--; //FIXME: Should ensure we are within bounds when rewinding
    }
}

//Gets the current character being parsed from the parse string
char get_parse_char(struct parse_data * data) {
    if (data && data->parse_ptr) {
        return *(data->parse_ptr);
    }
    return '\0';
}

// !!! ALLOCATES MEMORY, but is freed when parse_data is cleaned up or consumed !!!
// Loads a string to parse into a parse_data struct
void load_parse_string(struct parse_data * data, //parse_data struct in use
                       char * parse_string) //string to parse
{

    if (parse_string == NULL)
        parse_string = "";

    data->parse_ptr = data->parse_str_start = data->parse_str = parse_string;
    data->parse_str_end = data->parse_str_start + strlen(data->parse_str);

    if (data->accum_name != NULL) {
        free(data->accum_name);
    }
    if (data->accum_arg != NULL) {
        free(data->accum_arg);
    }
    data->accum_sz = 256; //FIXME: Should get back to dynamically reallocating here
    data->accum_name = malloc(data->accum_sz);
    data->accum_arg = malloc(data->accum_sz);

    data->name_ptr = data->accum_name;
    data->arg_ptr = data->accum_arg;
}

// !!! ALLOCATES MEMORY, but is cleaned up when state list is cleaned up !!!
// Adds an edge (aka transition) to a given state
struct parse_state * add_transition(struct parse_state * state, //state to add transition to
                                    bool (* condition)(char), //function to evaluate current character being parsed, if it returns true, this transition is followed
                                    void (* action)(struct parse_data *, char), //function to perform any associated action to the parse_data when this transition is followed
                                    struct parse_state * destination) //state to change to when this transition is followed
{
    struct state_transition * transitions;

    transitions = malloc(sizeof(struct state_transition));
    transitions->next = state->transitions;
    transitions->condition = condition;
    transitions->action = action;
    transitions->destination = destination;
    state->transitions = transitions;
    return state;
}

// !!! ALLOCATES MEMORY !!!
// !!! MUST CALL free_parse_state_list() on state_list !!!
// Creates and adds a parse_state struct to a state list so that it can be used now and is easier to clean up later
// Returns: created, allocated, populated parse_state struct
struct parse_state * add_parse_state(struct state_list * head_state_list_node, //state_list struct that is tracking allocated parse_state structs
                                     void(* error_action)(struct parse_data *, char), //fall-through transition, for when no other transitions apply
                                     char * name) //name of state (helpful for debugging)
{
    struct state_list * list_node;
    struct parse_state * state;

    list_node = malloc(sizeof(struct state_list));
    list_node->next = head_state_list_node->next;
    state = malloc(sizeof(struct parse_state));
    state->transitions = NULL;
    state->error_action = error_action;
    state->name = name;

    list_node->state = state;
    head_state_list_node->next = list_node;
    return state;
}

//Frees a state_list and its associated transitions
void free_parse_state_list(struct state_list * head_node) {
    struct parse_state * state;
    struct state_transition * t;
    struct state_list * tmp_node_to_free;

    head_node = head_node->next;
    while (head_node != NULL) {
        state = head_node->state;
        while (state->transitions != NULL) {
            t = state->transitions;
            state->transitions = t->next;
            free(t);
        }
        free(state);

        tmp_node_to_free = head_node;
        head_node = head_node->next;
        if (tmp_node_to_free != NULL) {
            free(tmp_node_to_free);
        }
    }
}

//Adds a rule to the management engine from arbitrary string inputs
int apply_rule(char * name, //the name to give the rule
               struct fn * conditions, //a string containing a space separated set of conditions the rule will have
               struct fn * actions, //a string containing a space separated set of actions the rule will have
               struct fn * undo_actions, //a string containing a space separated set of undo actions the rule will have
               char ** err) //A reference to a preallocated char *, overwritten by this function; usually data->message
{

    struct fn_arg * fn_arg;
    struct fn * fn;
    struct rule * rule;
    struct condition * condition;
    struct arg_node arg;
    struct action * action;
    int recoverable_err = 0;
    int parse_err = NO_PARSE_ERROR;
    int rule_err;


    rule = new_rule(clone_string(name));
    while ((fn = conditions)) {
        condition = new_condition_from_string(fn->name);

        if (condition == NULL) {
            recoverable_err |= BAD_CONDITION;
            xcpmd_log(LOG_WARNING, "no condition type named %s; omitting...\n", fn->name);
            safe_str_append(err, "recoverable error: no condition type named %s.\n", fn->name);
            while ((fn_arg = fn->args))
                fn->args = pop_and_free_arg(fn_arg);
            conditions = pop_and_free_fn(fn);
            continue;
        }

        if (fn->undo == false) {
            invert_condition(condition);
        }

        while ((fn_arg = fn->args)) {
            arg = conv_fn_arg(*fn_arg);
            if (arg.type == ARG_STR)
                arg.arg.str = clone_string(arg.arg.str);
            if (arg.type == ARG_VAR)
                arg.arg.var_name = clone_string(arg.arg.var_name);
            add_condition_arg(condition, arg.type, arg.arg);
            fn->args = pop_and_free_arg(fn_arg);
        }
        add_condition_to_rule(rule, condition);
        conditions = pop_and_free_fn(fn);
    }
    while ((fn = actions)) {
        action = new_action_from_string(fn->name);

        if (action == NULL) {
            recoverable_err |= BAD_ACTION;
            xcpmd_log(LOG_WARNING, "no action type named %s; omitting...\n", fn->name);
            safe_str_append(err, "recoverable error: no action type named %s.\n", fn->name);
            while ((fn_arg = fn->args))
                fn->args = pop_and_free_arg(fn_arg);
            actions = pop_and_free_fn(fn);
            continue;
        }

        while ((fn_arg = fn->args)) {
            arg = conv_fn_arg(*fn_arg);
            if (arg.type == ARG_STR)
                arg.arg.str = clone_string(arg.arg.str);
            if (arg.type == ARG_VAR)
                arg.arg.var_name = clone_string(arg.arg.var_name);
            add_action_arg(action, arg.type, arg.arg);
            fn->args = pop_and_free_arg(fn_arg);
        }
        add_action_to_rule(rule, action);
        actions = pop_and_free_fn(fn);
    }
    while ((fn = undo_actions)) {
        action = new_action_from_string(fn->name);

        if (action == NULL) {
            recoverable_err |= BAD_UNDO;
            xcpmd_log(LOG_WARNING, "no action type named %s; omitting...\n", fn->name);
            safe_str_append(err, "recoverable error: no action type named %s.\n", fn->name);
            while ((fn_arg = fn->args))
                fn->args = pop_and_free_arg(fn_arg);
            undo_actions = pop_and_free_fn(fn);
            continue;
        }

        while ((fn_arg = fn->args)) {
            arg = conv_fn_arg(*fn_arg);
            if (arg.type == ARG_STR)
                arg.arg.str = clone_string(arg.arg.str);
            if (arg.type == ARG_VAR)
                arg.arg.var_name = clone_string(arg.arg.var_name);
            add_action_arg(action, arg.type, arg.arg);
            fn->args = pop_and_free_arg(fn_arg);
        }
        add_undo_to_rule(rule, action);
        undo_actions = pop_and_free_fn(fn);
    }

    rule_err = validate_rule(rule, err);
    if (rule_err == RULE_VALID) {
        add_rule(rule);
        if (recoverable_err != 0)
            parse_err = RECOVERABLE_ERROR;
        else
            parse_err = NO_PARSE_ERROR;
    }
    else {
        delete_rule(rule);
    }

    return (parse_err | recoverable_err | rule_err);
}


/* All possible transition conditions for state machine (these are NOT rule conditions!) */
//All conditions return a bool that is true when the condition is satisfied or false otherwise, and take a single char parameter of the current char being parsed
//The conditions below are self documenting
bool condition_isAlphanumeric(char c) {
    return ( ((c >= 'A')&&(c <= 'Z')) || ((c >= 'a')&&(c <= 'z')) || ((c >= '0')&&(c <= '9')) );
}

bool condition_isAlphanumeric_(char c) {
    return ( (c == '_') || ((c >= 'A')&&(c <= 'Z')) || ((c >= 'a')&&(c <= 'z')) || ((c >= '0')&&(c <= '9')) );
}

bool condition_isDblQuote(char c) {
    return (c == '"');
}

bool condition_isDblQuoteOrNull(char c) {
    return (c == '"') || (c == '\0');
}

bool condition_isNotDblQuoteOrNull(char c) {
    return ( (c != '"') && (c != '\0') ) ;
}

bool condition_isPeriod(char c) {
    return (c == '.');
}

bool condition_isDigit(char c) {
    return ( (c >= '0')&&(c <= '9') );
}

bool condition_isDigitOrMinus(char c) {
    return (( (c >= '0')&&(c <= '9') ) || (c == '-'));
}

bool condition_isSpace(char c) {
    return (c == ' ');
}

bool condition_isExclaimation(char c) {
    return (c == '!');
}

bool condition_isOpenParen(char c) {
    return (c == '(');
}

bool condition_isClosedParen(char c) {
    return (c == ')');
}

bool condition_isDollarSign(char c) {
    return (c == '$');
}

bool condition_isPlus(char c) {
    return (c == '+');
}

bool condition_isMinus(char c) {
    return (c == '-');
}

bool condition_isTrue(char c) {
    return ( (c == 't') || (c == 'T') || (c == 'y') || (c == 'Y') );
}

bool condition_isFalse(char c) {
    return ( (c == 'f') || (c == 'F') || (c == 'n') || (c == 'N') );
}

bool condition_isNull(char c) {
    return (c == '\0');
}

bool condition_isNewline(char c) {
    return (c == '\n');
}


/* All possible transition actions for state machine (these are NOT rule actions!) */
//All actions return void and take the parse_data struct that is currently in use and the current character being parsed

//Accepts current character as a member of the name string
void action_accumName(struct parse_data * data, char c) {
    *(data->name_ptr++) = c;
}

//Reacts to parsing an inversion symbol ("!")
void action_invertFn(struct parse_data * data, char c) {
    data->undo = false;
}

//Accepts current character as a member of an argument (to be converted after accumulation)
void action_accumArg(struct parse_data * data, char c) {
    *(data->arg_ptr++) = c;
}

//Establishes the current argument being accumulated as a variable, reacts to parsing a variable symbol ("$")
void action_beginAccumVar(struct parse_data * data, char c) {
    data->arg_type = TYPE_VAR;
}

//Establishes the current argument being accumulated as an integer and accepts the current character as a member of that argument
void action_beginAccumInt(struct parse_data * data, char c) {
    data->arg_type = TYPE_INT;
    action_accumArg(data, c);
}

//Establishes the current argument being accumulated as a float and accepts the current character as a member of that argument
void action_beginAccumFloat(struct parse_data * data, char c) {
    data->arg_type = TYPE_FLOAT;
    action_accumArg(data, c);
}

//Establishes the current argument being accumulated as a string, reacts to parsing an opening double quote for a string
void action_beginAccumStr(struct parse_data * data, char c) {
    data->arg_type = TYPE_STR;
    //We do not accum a character because opening double quote doesn't count
}

//Establishes the current argument being accumulated as a boolean and accumulates a 't' character as the entire argument
void action_beginAccumTrue(struct parse_data * data, char c) {
    data->arg_type = TYPE_BOOL;
    action_accumArg(data, 't');
}

//Establishes the current argument being accumulated as a boolean and accumulates a 'f' character as the entire argument
void action_beginAccumFalse(struct parse_data * data, char c) {
    data->arg_type = TYPE_BOOL;
    action_accumArg(data, 'f');
}

// !!! ALLOCATES MEMORY, but is cleaned up when parse_data is cleaned up or consumed !!!
//Accepts the data within the current argument accumulator as whatever type has been established, adds the accepted argument to data->args struct fn_arg list
void action_acceptArg(struct parse_data * data, char c) {
    union fn_arg_val val;
    struct fn_arg * arg;
    bool resolved;
    char * str;
    struct db_var * db_var;

    *(data->arg_ptr) = '\0';
    if (strlen(data->accum_arg) <= 0) {
        return;
    }

    switch (data->arg_type) {
    case TYPE_INT:
        sscanf(data->accum_arg, "%ld", &(val.as_int));
        break;
    case TYPE_FLOAT:
        sscanf(data->accum_arg, "%f", &(val.as_float));
        break;
    case TYPE_STR:
        val.as_str = strdup(data->accum_arg);
        break;
    case TYPE_BOOL:
        if (data->accum_arg[0] == 't') {
            val.as_bool = true;
        }
        else if (data->accum_arg[0] == 'f') {
            val.as_bool = false;
        }
        else {
            error(data, "boolean type detected but argument accumulator has invalid data (%s)", data->accum_arg);
            data->error_code = BOOL_ERROR;
            data->finished = true;
            return;
        }
        break;
    case TYPE_VAR:
        resolved = get_var_from_map(data->var_map, data->accum_arg, &val, &(data->arg_type));
        db_var = lookup_var(data->accum_arg);
        if (resolved == false && db_var == NULL) {
            error(data, "unable to resolve variable %s", data->accum_arg);
            data->error_code = VAR_MISSING;
            data->finished = true;
            return;
        }
        str = data->accum_arg;
        val.as_str = strdup(str);
        data->arg_type = TYPE_VAR;
        break;
    case TYPE_UNDETERMINED:
    default:
        error(data, "invalid parsing mode: %d", data->arg_type); //make user friendly, include data
        data->error_code = FSM_ERROR;
        data->finished = true;
        return;
        break;
    }
    arg = new_fn_arg(data->args_tail, val, data->arg_type);
    if (data->args == NULL) {
        data->args = arg;
    }
    data->args_tail = arg;
    data->arg_ptr = data->accum_arg;
}

//Accepts the current argument (if there is one), sets the fn_arg struct list (data->args) as the fn struct's args, and sets the currently accumulated name as the
//fn struct's name. The fn struct is then added to a list of fn structs associated with the current parse target.
void action_acceptFn(struct parse_data * data, char c) {
    struct fn * fn;

    action_acceptArg(data, c);
    *(data->name_ptr) = '\0';
    if (strlen(data->accum_name) <= 0) {
        return;
    }
    switch (data->parsing) {
    case TYPE_ARG:
        fn = new_fn(data->parsed_arg, data->accum_name, data->args, false);
        data->parsed_arg = fn;
        break;
    case TYPE_CONDITION:
        fn = new_fn(data->conditions_tail, data->accum_name, data->args, data->undo);
        if (data->conditions == NULL) {
            data->conditions = fn;
        }
        data->conditions_tail = fn;
        break;
    case TYPE_ACTION:
        fn = new_fn(data->actions_tail, data->accum_name, data->args, data->undo);
        if (data->actions == NULL) {
            data->actions = fn;
        }
        data->actions_tail = fn;
        break;
    case TYPE_UNDO_ACTION:
        fn = new_fn(data->undo_actions_tail, data->accum_name, data->args, false);
        if (data->undo_actions == NULL) {
            data->undo_actions = fn;
        }
        data->undo_actions_tail = fn;
        break;
    case TYPE_VAR_MAP:
        if (data->args == NULL) {
            error(data, "var map entry %s has no value", data->accum_name); //say which
            data->error_code = VAR_MISSING;
            data->finished = true;
            return;
        }
        if ( (data->args != data->args_tail) || (data->args->next != NULL) ) {
            //if ( (data->args != data->args_tail) )
            //    DBGOUT("UNEQUAL TAIL");
            //if ( (data->args->next != NULL) )
            //    output_fn_arg(data->args->next);

            error(data, "var map entry %s has multiple values", data->accum_name); //say which
            data->error_code = OVERLAPPING_VARS;
            data->finished = true;
            return;
        }
        switch (data->args->type ) {
        case TYPE_INT:
        case TYPE_FLOAT:
        case TYPE_STR:
        case TYPE_BOOL:
            break;
        default:
            error(data, "var map entry had value of incompatible type"); //say what entry and what type
            data->error_code = INVALID_VAR_TYPE;
            data->finished = true;
            return;
        }
        data->error_code = add_to_var_map_as_arg(data->var_map, data->accum_name, data->args, &data->message);
        break;
    default:
        error(data, "invalid parsing mode");
        data->error_code = FSM_ERROR;
        data->finished = true;
        return;
    }
    data->args = NULL; //All args must be consumed by this point!
    data->args_tail = NULL;
    data->name_ptr = data->accum_name;
    data->undo = true;
}

//Accepts all fn structs that are associated with the current parse target (no action required since they're already stored on a per-target basis).
//Advances the parsing to the next parse target if there is one, or finishes parsing by accepting the meta-target parse target (e.g. TYPE_RULE).
void action_acceptFns(struct parse_data * data, char c) {

    int err, parse_err, rule_err, recoverable_err;

    action_acceptFn(data, c);
    switch (data->parsing) {
    case TYPE_ARG:
        data->parsing = TYPE_UNDETERMINED;
        data->finished = true;
        break;
    case TYPE_CONDITION:
        data->parsing = TYPE_ACTION;
        load_parse_string(data, data->actions_str);
        break;
    case TYPE_ACTION:
        data->parsing = TYPE_UNDO_ACTION;
        load_parse_string(data, data->undo_actions_str);
        break;
    case TYPE_UNDO_ACTION:
        //DBGOUT("\n");
        err = apply_rule(data->rule_name, data->conditions, data->actions, data->undo_actions, &data->message);
        parse_err = err & PARSE_ERROR_MASK;
        recoverable_err = err & RECOVERABLE_MASK;
        rule_err = err & RULE_ERROR_MASK;

        if (rule_err == RULE_VALID) {
            if (parse_err == RECOVERABLE_ERROR) {
                data->error_code = RECOVERABLE_ERROR;
                data->rule_error_code = recoverable_err;
            }
            else if (parse_err == NO_PARSE_ERROR) {
                data->error_code = NO_PARSE_ERROR;
                data->rule_error_code = RULE_CODE_NOT_SET;
            }
            else {
                data->error_code = parse_err;
                data->rule_error_code = RULE_CODE_NOT_SET;
            }
        }
        else {
            data->error_code = RULE_INVALID;
            data->rule_error_code = rule_err;
        }
        data->parsing = TYPE_UNDETERMINED;
        data->finished = true;
        data->actions_tail = data->actions = NULL;
        data->conditions_tail = data->conditions = NULL;
        data->undo_actions_tail = data->undo_actions = NULL;
        break;
    case TYPE_VAR_MAP:
        //DBGOUT("\n");
        //output_fns(data->var_map->vars_as_fns);
        data->parsing = TYPE_UNDETERMINED;
        data->finished = true;
        break;
    default:
        error(data, "Parsing mode is unexpected type - this is likely a bug");
        data->error_code = FSM_ERROR;
        data->finished = true;
        break;
    }
}

/* All possible transition errors for state machine (used for when a state fails to transition) */
//All errors return void and take the parse_data struct that is currently in use and the current character being parsed
//The errors functions below are self documenting
void error_onStart(struct parse_data * data, char c) {
    parse_error(data, "an inverter [!], function name [A-Z a-z 0-9 _], or end of input [NUL]", c);
}

void error_onAccumName(struct parse_data * data, char c) {
    parse_error(data, "a function name [A-Z a-z 0-9 _]", c);
}

void error_onGenericArg(struct parse_data * data, char c) {
    parse_error(data, "an argument of some sort: int[0-9], bool[t/f], float[0-9], string[\"], or var[$]", c);
}

void error_onAccumVar(struct parse_data * data, char c) {
    parse_error(data, "a variable identifier [A-Z a-z 0-9 _", c);
}

void error_onIntArg(struct parse_data * data, char c) {
    parse_error(data, "an integer [0-9]", c);
}

void error_onFloatArg(struct parse_data * data, char c) {
    parse_error(data, "a floating point value [0-9 .]", c);
}

void error_onFloatArgPostPeriod(struct parse_data * data, char c) {
    parse_error(data, "a floating point value [0-9]", c);
}

void error_onStrArg(struct parse_data * data, char c) {
    parse_error(data, "to not enter this error state, \"onStrArg\", for all possible characters are accounted for with transitions", c);
}

void error_onArgEnd(struct parse_data * data, char c) {
    parse_error(data, "a space delimiter or function closure [space or )]", c);
}

void error_onAcceptFn(struct parse_data * data, char c) {
    parse_error(data, "a space delimiter or end of input [space or NUL or newline]", c);
}

void error_default(struct parse_data * data, char c) {
    parse_error(data, "to not enter this error state, \"onAcceptRule\", for this is a final state", c);
}

//@@STATE_MACHINE@@
//Used to build the parser itself by defining all states and transitions, and assocating conditions, actions, and errors with those transitions, and adding all
//states to a the parser state_list struct. All edits to the parser state machine go here and to the conditions/actions/errors associated.
//Returns the starting parse_state and takes an allocated, empty state_list struct as a head node to build the list on
struct parse_state * build_parse_state_list(struct state_list * head_node) {

    //State declarations
    struct parse_state * state_start;
    struct parse_state * state_invertFn;
    struct parse_state * state_accumName;
    struct parse_state * state_beginAccumArg;
    struct parse_state * state_accumVar;
    struct parse_state * state_accumInt;
    struct parse_state * state_beginAccumFloat;
    struct parse_state * state_accumFloat;
    struct parse_state * state_accumStr;
    struct parse_state * state_endAccumStr;
    struct parse_state * state_accumBool;
    struct parse_state * state_acceptFn;
    struct parse_state * state_acceptRule;

    //State definitions
    state_start = add_parse_state(head_node, error_onStart, "start");
    state_invertFn = add_parse_state(head_node, error_onAccumName, "invertFn");
    state_accumName = add_parse_state(head_node, error_onAccumName, "accumName");
    state_beginAccumArg = add_parse_state(head_node, error_onGenericArg, "beginAccumArg");
    state_accumVar = add_parse_state(head_node, error_onAccumVar, "accumVar");
    state_accumInt = add_parse_state(head_node, error_onIntArg, "accumInt");
    state_beginAccumFloat = add_parse_state(head_node, error_onFloatArg, "beginAccumFloat");
    state_accumFloat = add_parse_state(head_node, error_onFloatArgPostPeriod, "accumFloat");
    state_accumStr = add_parse_state(head_node, error_onStrArg, "accumStr");
    state_endAccumStr = add_parse_state(head_node, error_onArgEnd, "endAccumStr");
    state_accumBool = add_parse_state(head_node, error_onArgEnd, "accumBool");
    state_acceptFn = add_parse_state(head_node, error_onAcceptFn, "acceptFn");
    state_acceptRule = add_parse_state(head_node, error_default, "acceptRule");


    //State transition definitions (automatically declared and managed)
    add_transition(state_start, &condition_isAlphanumeric_, &action_accumName, state_accumName);
    add_transition(state_start, &condition_isExclaimation, &action_invertFn, state_invertFn);
    add_transition(state_start, &condition_isSpace, NULL, state_start);
    add_transition(state_start, &condition_isNull, &action_acceptFns, state_acceptRule);
    add_transition(state_start, &condition_isNewline, &action_acceptFns, state_acceptRule);

    add_transition(state_invertFn, &condition_isAlphanumeric_, &action_accumName, state_accumName);

    add_transition(state_accumName, &condition_isAlphanumeric_, &action_accumName, state_accumName);
    add_transition(state_accumName, &condition_isOpenParen, NULL, state_beginAccumArg);

    add_transition(state_beginAccumArg, &condition_isDollarSign, &action_beginAccumVar, state_accumVar);
    add_transition(state_beginAccumArg, &condition_isDigitOrMinus, &action_beginAccumInt, state_accumInt);
    add_transition(state_beginAccumArg, &condition_isDblQuote, &action_beginAccumStr, state_accumStr);
    add_transition(state_beginAccumArg, &condition_isTrue, &action_beginAccumTrue, state_accumBool);
    add_transition(state_beginAccumArg, &condition_isFalse, &action_beginAccumFalse, state_accumBool);
    add_transition(state_beginAccumArg, &condition_isClosedParen, &action_acceptFn, state_acceptFn);

    add_transition(state_accumVar, &condition_isAlphanumeric_, &action_accumArg, state_accumVar);
    add_transition(state_accumVar, &condition_isSpace, &action_acceptArg, state_beginAccumArg);
    add_transition(state_accumVar, &condition_isClosedParen, &action_acceptFn, state_acceptFn);

    add_transition(state_accumInt, &condition_isDigit, &action_accumArg, state_accumInt);
    add_transition(state_accumInt, &condition_isPeriod, &action_beginAccumFloat, state_beginAccumFloat);
    add_transition(state_accumInt, &condition_isSpace, &action_acceptArg, state_beginAccumArg);
    add_transition(state_accumInt, &condition_isClosedParen, &action_acceptFn, state_acceptFn);

    add_transition(state_beginAccumFloat, &condition_isDigit, &action_accumArg, state_accumFloat);
    add_transition(state_beginAccumFloat, &condition_isClosedParen, &action_acceptFn, state_acceptFn);

    add_transition(state_accumFloat, &condition_isDigit, &action_accumArg, state_accumFloat);
    add_transition(state_accumFloat, &condition_isSpace, &action_acceptArg, state_beginAccumArg);
    add_transition(state_accumFloat, &condition_isClosedParen, &action_acceptFn, state_acceptFn);

    add_transition(state_accumStr, &condition_isNotDblQuoteOrNull, &action_accumArg, state_accumStr);
    add_transition(state_accumStr, &condition_isDblQuoteOrNull, NULL, state_endAccumStr);

    add_transition(state_accumBool, &condition_isSpace, &action_acceptArg, state_beginAccumArg);
    add_transition(state_accumBool, &condition_isClosedParen, &action_acceptFn, state_acceptFn);

    add_transition(state_endAccumStr, &condition_isSpace, &action_acceptArg, state_beginAccumArg);
    add_transition(state_endAccumStr, &condition_isClosedParen, &action_acceptFn, state_acceptFn);

    add_transition(state_acceptFn, &condition_isSpace, NULL, state_start);
    add_transition(state_acceptFn, &condition_isNull, &action_acceptFns, state_acceptRule);
    add_transition(state_acceptFn, &condition_isNewline, &action_acceptFns, state_acceptRule);

    //No transitions for state_acceptRule as it is final


    //Always return the starting node
    return state_start;
}

//Parses a given string using the state machine that is attached to data->state, which is used as a starting state
//Returns true if parsing was successful, false otherwise
bool parse(struct parse_data *data, //current parse_data struct
           char * str) //first string to parse (other strings may be called in from parse_data by load_parse_string during the parse)
{
    struct state_transition * transition;
    char current;

    //Get the first string into position
    load_parse_string(data, str); //TODO: I don't like that we provide a string as our first str, and then other strings get loaded in later, feels like voodoo
                                  //Instead, maybe we should have it take NULL as the str and do the voodoo all in one place so its not obfuscated.

    //Set up requisite entry information
    transition = data->state->transitions;
    current = get_parse_char(data);
    data->error_code = NO_PARSE_ERROR;
    data->rule_error_code = RULE_CODE_NOT_SET;


    //State machine main loop
    while (false == data->finished) {

        while (transition != NULL) {
            if (transition->condition(current)) {
                //DBGOUT("%c|", current);
                if (data->parse_ptr != data->parse_str_end)
                    adv_parse_ptr(data); //Must come first because some actions load new strings
                if (transition->action) {
                    transition->action(data, current);
                }
                data->state = transition->destination;
                //Re-setup loop entry information
                transition = data->state->transitions;
                current = get_parse_char(data);
                if (true == data->finished) {
                    break;
                }
            }
            else {
                transition = transition->next;
            }
        }
        if (data->state->transitions != NULL) {
            if (false == data->finished) {
                data->state->error_action(data, current);
                data->error_code = FSM_ERROR;
            }
            return false;
        }
        //Not done? Re-setup current state as start state
        data->state = data->start_state;
        //Re-setup loop entry information
        transition = data->state->transitions;
        current = get_parse_char(data);
    }
    if (data->error_code == NO_PARSE_ERROR)
        return true;
    else
        return false;
}


//Loads variables and rules from the DB, returns 0 if successful, -1 otherwise
int parse_config_from_db() {

    struct state_list states;
    struct var_map var_map;
    struct parse_data data;
    bool ret;

    init_state_list(&states);
    init_var_map(&var_map);

    memset(&data, 0, sizeof(struct parse_data));
    memset(&var_map, 0, sizeof(struct var_map));

    init_parse_data(&data, &var_map, build_parse_state_list(&states), NULL, NULL, NULL, NULL, NULL, TYPE_UNDETERMINED);
    if (parse_db_vars(&data)) {
        if(!parse_db_rules(&data)) {
            xcpmd_log(LOG_WARNING, "Error parsing db rules - %s.\n", extract_parse_error(&data));
            ret = -1;
        }
        else {
            ret = 0;
        }
    }
    else {
        xcpmd_log(LOG_WARNING, "Error parsing db vars - %s.\n", extract_parse_error(&data));
        ret = -1;
    }

    cleanup_parse_data(&data);
    free_var_map(&var_map);
    free_parse_state_list(&states);

    return ret;
}


//Parses and adds a variable to existing parse_data.
bool parse_var_persistent(struct parse_data * data, char * var_string) {

    init_parse_data(data, data->var_map, data->start_state, NULL, var_string, NULL, NULL, NULL, TYPE_VAR_MAP);
    return parse(data, data->var_map_str);
}


//Parses and adds a rule to existing parse_data.
bool parse_rule_persistent(struct parse_data * data, char * name, char * conditions, char * actions, char * undos) {

    init_parse_data(data, data->var_map, data->start_state, name, NULL, conditions, actions, undos, TYPE_RULE);
    return parse(data, data->conditions_str);
}


//Indicate that a parsing-related error occurred externally.
void external_error(struct parse_data * data, int error_code, char * error_string) {

    data->error_code = error_code;
    error_append(data, error_string);
}

//Sets up the parser state machine and adds a single rule.
bool dbus_add_rule(char * name,       //rule name
                   char * conditions, //space-separated list of conditions
                   char * actions,    //space-separated list of actions
                   char * undos,      //space-separated list of undo actions
                   char ** error) //A reference to a preallocated char *, overwritten by this function; usually data->message
{

    struct state_list states;
    struct var_map var_map;
    struct parse_data data;
    struct rule * rule;
    bool ret;

    init_state_list(&states);
    init_var_map(&var_map);

    memset(&data, 0, sizeof(struct parse_data));
    memset(&var_map, 0, sizeof(struct var_map));

    init_parse_data(&data, &var_map, build_parse_state_list(&states), NULL, NULL, NULL, NULL, NULL, TYPE_UNDETERMINED); //TODO: Maybe keep this around in a global
    if (parse_db_vars(&data)) {
        if (parse_rule_persistent(&data, name, conditions, actions, undos)) {
            rule = get_rule_tail();
            write_db_rule(rule);
            ret = true;
        }
        else {
            if ((data.error_code & PARSE_ERROR_MASK) == RECOVERABLE_ERROR) {
                safe_str_append(error, "%s", extract_parse_error(&data));
                rule = get_rule_tail();
                write_db_rule(rule);
                ret = false;
            }
            else {
                safe_str_append(error, "couldn't parse rule %s: %s", name, extract_parse_error(&data));
                ret = false;
            }
        }
    }
    else {
        safe_str_append(error, "couldn't parse varmap: %s", data.message);
        ret = false;
    }

    cleanup_parse_data(&data);
    free_var_map(&var_map);
    free_parse_state_list(&states);

    return ret;
}


//Sets up the parser FSM and adds a single rule.
bool parse_rule(char * name,       //rule name
                char * conditions, //space-separated list of conditions
                char * actions,    //space-separated list of actions
                char * undos,      //space-separated list of undo actions
                char ** error) //A reference to a preallocated char *, overwritten by this function; usually data->message
{

    struct state_list states;
    struct var_map var_map;
    struct parse_data data;
    struct rule * rule;
    bool ret;

    init_state_list(&states);
    init_var_map(&var_map);

    memset(&data, 0, sizeof(struct parse_data));
    memset(&var_map, 0, sizeof(struct var_map));

    init_parse_data(&data, &var_map, build_parse_state_list(&states), NULL, NULL, NULL, NULL, NULL, TYPE_UNDETERMINED);
    if (parse_db_vars(&data)) {
        if (parse_rule_persistent(&data, name, conditions, actions, undos)) {
            rule = get_rule_tail();
            write_db_rule(rule);
            ret = true;
        }
        else {
            if ((data.error_code & PARSE_ERROR_MASK) == RECOVERABLE_ERROR) {
                safe_str_append(error, "%s", extract_parse_error(&data));
                rule = get_rule_tail();
                write_db_rule(rule);
                ret = false;
            }
            else {
                safe_str_append(error, "couldn't parse rule %s: %s", name, extract_parse_error(&data));
                ret = false;
            }
        }
    }
    else {
        safe_str_append(error, "couldn't parse varmap: %s", data.message);
        ret = false;
    }

    cleanup_parse_data(&data);
    free_var_map(&var_map);
    free_parse_state_list(&states);

    return ret;
}


//Sets up the parser state machine and adds or modifies a single variable. //TODO: More depth
bool parse_var(char * var_string, //string of the form varname(value)
               char ** error) //A reference to a preallocated char *, overwritten by this function; usually data->message
{

    struct state_list states;
    struct var_map var_map;
    struct parse_data data;
    bool ret;

    init_state_list(&states);
    init_var_map(&var_map);

    memset(&data, 0, sizeof(struct parse_data));
    memset(&var_map, 0, sizeof(struct var_map));

    init_parse_data(&data, &var_map, build_parse_state_list(&states), NULL, NULL, NULL, NULL, NULL, TYPE_UNDETERMINED);
    init_parse_data(&data, &var_map, data.start_state, NULL, var_string, NULL, NULL, NULL, TYPE_VAR_MAP);
    if (parse(&data, data.var_map_str)) {
        ret = true;
    }
    else {
        safe_str_append(error, "couldn't parse variable %s: %s", var_string, extract_parse_error(&data));
        ret = false;
    }

    cleanup_parse_data(&data);
    free_var_map(&var_map);
    free_parse_state_list(&states);

    return ret;
}

//Sets up the parser FSM and parses a single argument for type and value.
//Used when parsing DB variables.
bool parse_arg(char * arg_string,         //a string containing an argument literal value to be evaluated by the parser
               struct arg_node * arg_out, //reference to a preallocated struct to be backfilled with parsed value
               char ** error)   //A reference to a preallocated char *, overwritten by this function; usually data->message
{

    struct state_list states;
    struct var_map var_map;
    struct parse_data data;
    struct arg_node tmp_arg;
    bool ret;

    init_state_list(&states);
    init_var_map(&var_map);

    memset(&data, 0, sizeof(struct parse_data));
    memset(&var_map, 0, sizeof(struct var_map));

    init_parse_data(&data, &var_map, build_parse_state_list(&states), NULL, NULL, NULL, NULL, NULL, TYPE_UNDETERMINED);
    init_parse_data(&data, &var_map, data.start_state, NULL, arg_string, NULL, NULL, NULL, TYPE_ARG);
    if (parse(&data, data.var_map_str)) {

        tmp_arg = conv_fn_arg(*data.parsed_arg->args);
        if (tmp_arg.type == ARG_STR) {
            tmp_arg.arg.str = clone_string(tmp_arg.arg.str);
        }
        else if (tmp_arg.type == ARG_VAR) {
            tmp_arg.arg.var_name = clone_string(tmp_arg.arg.var_name);
        }
        pop_and_free_fn(data.parsed_arg);
        data.parsed_arg = NULL;

        *arg_out = tmp_arg;
        ret = true;
    }
    else {
        safe_str_append(error, "couldn't parse arg %s: %s", arg_string, extract_parse_error(&data));
        ret = false;
    }

    cleanup_parse_data(&data);
    free_var_map(&var_map);
    free_parse_state_list(&states);

    return ret;
}

//Extracts a parse error out of the provided parse_data struct and returns a string for error codes that do not allow custom messages
char * extract_parse_error(struct parse_data * data) {

    char * out;

    switch(data->error_code) {
        case RULE_INVALID:
        switch(data->rule_error_code) {
            case NO_NAME:
                out = "no rule name supplied";
                break;
            case NO_CONDITIONS:
                out = "no valid conditions supplied";
                break;
            case NO_ACTIONS:
                out = "at least one valid action or undo action required";
                break;
            case NAME_COLLISION:
                out = "a rule by that name already exists";
                break;
            case BAD_PROTO:
                out = data->message;
                break;
            default:
                out = "rule is invalid, but no reason given";
        }
        break;
        case RECOVERABLE_ERROR:
            out = data->message;
            break;
        case NO_PARSE_ERROR:
            out = "parser returned false but gave no error code.";
            break;
        default:
            if (strlen(data->message) > 0) {
                out = data->message;
            }
            else
                out = "no description provided";
    }

    return out;
}


//Test function which configures the policy engine from a file.
//Expects files to adopt the following format:
//First the variables section, then a section separator, then
//the rules section.
//The variables section has one and only one variable to a line.
//Variables are defined in the following form: varname(value)
//The section separator is a single line consisting of the '=' literal.
//The rules section has one and only one rule per line.
//Rules are comprised of fields, each separated by the '|' literal.
//Rule fields are as follows:
//rule name, conditions, optionally actions, and optionally undo actions. //TODO: Validate that an undo actions only rule is valid
//Each field is a string, formatting of each string is as follows:
//The rule name is an arbitrary string and must be unique between rules.
//Conditions, actions, and undo actions are formatted as: name(arguments)
//where the name is the name of the condition, action, or undo action
//and arguments is one or more space separated arguments
//Each argument or value may be one of the following types:
//String, integer, float, boolean, or variable
//Strings must be encapsulated in double quotes
//Integers are positive or negative numbers (prefix with '-' for negative,
//otherwise positive)
//Floats are floating point numbers and are composed of two integers
//separated by a "." literal. The integer to the right of the "." must be positive.
//Booleans are represented as literal "T" for true or "F" for false
//Variables begin with a "$" and are followed by the variable name (e.g. $var)
/* Example file:
var1("this is a string")
var2(75)
=
arbitrary_rule|battery_less_than($var2)|log_string($var1) sleep_vm("syncvm")
*/
int parse_config_from_file(char * filename) {

    struct state_list states;
    struct var_map var_map;
    struct parse_data data;
    char line[1024];
    int line_no = 0;
    char * name, *conditions, *actions, *undos;
    char *ptr, *token_start, *token_end, *string_end;
    bool in_var_section = true;
    bool in_quotes;
    bool whitespace_line;

    memset(&data, 0, sizeof(struct parse_data));
    memset(&var_map, 0, sizeof(struct var_map));

    init_state_list(&states);
    init_var_map(&var_map);

    init_parse_data(&data, &var_map, build_parse_state_list(&states), NULL, NULL, NULL, NULL, NULL, TYPE_UNDETERMINED);

    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        xcpmd_log(LOG_WARNING, "Couldn't open file %s - error code %d", filename, errno);
        return -1;
    }

    //For simplicity, separate into var and rule sections by a line containing an '=', with vars coming first.
    while (fgets(line, 1024, file)) {

        line_no++;
        xcpmd_log(LOG_DEBUG, "Parsing line %d: %s", line_no, line);

        //Discard any line beginning with a comment character (#).
        if (line[0] == '#')
            continue;

        //Discard any lines containing only whitespace.
        whitespace_line = false;
        ptr = line;
        while (*ptr <= ' ') {
            if (*ptr == '\0') {
                whitespace_line = true;
                break;
            }
            ++ptr;
        }
        if (whitespace_line) {
            xcpmd_log(LOG_DEBUG, "Line %d was whitespace.", line_no);
            continue;
        }

        //Discard any lines longer than 1024 characters.
        if (strchr(line, '\n') == NULL) {
            xcpmd_log(LOG_WARNING, "Line %d longer than 1024 characters. Skipping...\n", line_no);
            while (strchr(line, '\n') == NULL) {
                if (fgets(line, 1024, file) == NULL) {
                    break;
                }
            }
            continue;
        }

        //Check if we've hit a section separator.
        if (strchr(line, '=')) {
            in_var_section = false;
            continue;
        }

        //Parse each line.
        if (in_var_section) {

            init_parse_data(&data, &var_map, data.start_state, NULL, line, NULL, NULL, NULL, TYPE_VAR_MAP);
            if (!parse(&data, data.var_map_str)) {
                xcpmd_log(LOG_WARNING, "Error parsing var on line %d - %s.\n", line_no, extract_parse_error(&data));
                continue;
            }
        }
        else {
            //Get each section, separated by a '|'.
            token_start = ptr = line;
            name = conditions = actions = undos = NULL;
            in_quotes = false;
            string_end = strchr(line, '\0');
            while(ptr <= string_end) {

                if (*ptr == '\"')
                    in_quotes = !in_quotes;

                if ((*ptr == '|' || *ptr == '\0' || *ptr == '\n') && !in_quotes) {

                    *ptr = '\0';
                    if (name == NULL) {
                        //Chomp trailing garbage characters.
                        token_end = ptr;
                        while(*token_end < '!' || *token_end > '~') {
                            *token_end = '\0';
                            token_end -= sizeof(char);
                        }
                        name = token_start;
                    }
                    else if (conditions == NULL)
                        conditions = token_start;
                    else if (actions == NULL)
                        actions = token_start;
                    else if (undos == NULL)
                        undos = token_start;
                    else    //trailing pipes
                        break;

                    token_start = ptr + sizeof(char);
                }
                ptr += sizeof(char);
            }

            init_parse_data(&data, &var_map, data.start_state, name, NULL, conditions, actions, undos, TYPE_RULE);
            if (!parse(&data, data.conditions_str)) {
                xcpmd_log(LOG_WARNING, "Error parsing rule on line %i - %s", line_no, extract_parse_error(&data));
            }
        }
    }

    cleanup_parse_data(&data);
    free_var_map(data.var_map);
    free_parse_state_list(&states);

    return 0;
}
