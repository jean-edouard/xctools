/*
 * db-helper.c
 *
 * Provide an interface for reading and writing to the DB.
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

#include <yajl/yajl_tree.h>
#include <yajl/yajl_gen.h>
#include "rpcgen/db_client.h"
#include "project.h"
#include "xcpmd.h"
#include "db-helper.h"

/**
 * This file contains functions for reading from and writing to the DB, both
 * low-level and high-level. Many of these allocate memory or have other side
 * effects, so be careful.
 *
 * Variables are implicitly written to the DB when accessed through the functions
 * exposed in db-helper.h, but rules must be written to the DB explicitly.
 *
 * Since variables will generally be read often and written rarely, and DB
 * access is relatively expensive, a write-through cache has been implemented.
 * Cache incoherence is avoided entirely if variables are accessed through the
 * methods in db-helper.h, but if the DB is modified through another pathway
 * (db-rm, for example), the cache can be reset with the load_policy_from_db RPC.
 *
 * Cached variables cannot be deleted if they are referred to by any rules, but
 * they can be overwritten at any time, provided there are no type conflicts.
 * Typing is strictly enforced; a variable cannot be overwritten if the new value
 * does not match its current type.
 * See rules.h for more on argument types.
 *
 * Functions for touching the variable cache are defined here, but its global
 * variable, db_vars, is set up and torn down in rules.c.
 */

//Function prototypes
static void db_write(char * path, char * value);
static void db_inject(char * path, char * json);
static char * db_read(char * path);
static void db_rm(char * path);
static char * db_dump_path(char * path);

static struct arg_node get_db_var(char * var_name);
static void write_db_var(char * name, enum arg_type type, union arg_u value);
static void delete_db_var(char * var_name);
static void delete_db_vars();

static char ** json_rule_to_parseable(char * name, char * json);
static char * rule_to_json(struct rule * rule);

static struct db_var * cache_db_var(char * name, enum arg_type type, union arg_u value);
static int uncache_db_var(char * name);


//Write a value to the specified DB path.
static void db_write(char * path, char * value) {

    com_citrix_xenclient_db_write_(xcdbus_conn, DB_SERVICE, DB_PATH, path, value);
}


//Writes a whole JSON blob to the specified DB path.
static void db_inject(char * path, char * json) {

    com_citrix_xenclient_db_inject_(xcdbus_conn, DB_SERVICE, DB_PATH, path, json);
}


//Allocates memory!
//Gets the value of the specified DB key.
//The string returned should be freed.
static char * db_read(char * path) {

    char * string;
    if (com_citrix_xenclient_db_read_(xcdbus_conn, DB_SERVICE, DB_PATH, path, &string)) {
        return string;
    }
    else {
        return NULL;
    }
}


//Remove the specified DB key.
static void db_rm(char * path) {

    com_citrix_xenclient_db_rm_(xcdbus_conn, DB_SERVICE, DB_PATH, path);
}


//Allocates memory!
//Dump the DB contents at the given path into a string.
//The string returned should be freed.
static char * db_dump_path(char * path) {

    char * string;
    if (com_citrix_xenclient_db_dump_(xcdbus_conn, DB_SERVICE, DB_PATH, path, &string)) {
        return string;
    }
    else {
        return NULL;
    }
}


//Writes a variable to the DB. Does not modify the internal cache.
static void write_db_var(char * name, enum arg_type type, union arg_u value) {

    char * var;
    char * path;

    var = arg_to_string(type, value);
    path = safe_sprintf("%s/%s", DB_VAR_MAP_PATH, name);
    db_write(path, var);
    free(var);
    free(path);
}


//May allocate memory!
//Reads a variable from the DB and parses it into an arg_node.
//Does not modify the internal cache.
//If the argument is a string, that string is malloc'd.
static struct arg_node get_db_var(char * var_name) {

    struct arg_node arg;
    char * path;
    char *var_value, *var_string;
    char * error;

    path = safe_sprintf("%s/%s", DB_VAR_MAP_PATH, var_name);
    var_value = db_read(path);

    if (var_value == NULL) {
        arg.type = ARG_NONE;
        arg.arg.i = 0;
        return arg;
    }

    if (var_value[0] != '\0') {
        var_string = safe_sprintf("%s(%s)", var_name, var_value);

        if (!parse_arg(var_string, &arg, &error)) {
            xcpmd_log(LOG_WARNING, "Var %s's DB entry (%s) was malformed: %s\n", var_name, var_value, error);
            arg.type = ARG_NONE;
            arg.arg.i = 0;
            free(error);
        }

        free(var_string);
    }
    else {
        arg.type = ARG_NONE;
        arg.arg.i = 0;
    }

    free(var_value);
    free(path);

    return arg;
}


//Deletes the specified variable from the DB. Does not modify the internal cache.
static void delete_db_var(char * var_name) {

    char * path;
    path = safe_sprintf("%s/%s", DB_VAR_MAP_PATH, var_name);
    db_rm(path);
    free(path);
}


//Deletes all variables in the DB. Does not modify the internal cache.
static void delete_db_vars() {

    db_rm(DB_VAR_MAP_PATH);
}


//Parse and cache all DB variables. Requires an initialized parse_data struct.
bool parse_db_vars(struct parse_data * parse_data) {

    char err[1024];
    char * json;
    char *var_name, *var_value, *var_string;
    yajl_val yajl;
    bool success = true;
    int i, num_vars;

    json = db_dump_path(DB_VAR_MAP_PATH);
    if (json == NULL) {
        xcpmd_log(LOG_WARNING, "Couldn't get variables from DB.");
        return false;
    }
    yajl = yajl_tree_parse(json, err, sizeof(err));

    if (YAJL_IS_OBJECT(yajl)) {

        num_vars = yajl->u.object.len;
        for (i = 0; i < num_vars; ++i) {

            if (YAJL_IS_STRING(yajl->u.object.values[i])) {
                var_name = (char *)yajl->u.object.keys[i];
                var_value = (char *)YAJL_GET_STRING(yajl->u.object.values[i]);
                var_string = safe_sprintf("%s(%s)", var_name, var_value);

                if (!parse_var_persistent(parse_data, var_string)) {
                    xcpmd_log(LOG_WARNING, "Error parsing var string %s: %s", var_string, extract_parse_error(parse_data));
                    success = false;
                }
                free(var_string);
            }
        }
    }

    free(json);
    yajl_tree_free(yajl);

    return success;
}


//Write the specified rule to the DB. Does not modify the internal rule list.
void write_db_rule(struct rule * rule) {

    char * json, *path;

    json = rule_to_json(rule);
    path = safe_sprintf("%s/%s", DB_RULE_PATH, rule->id);
    db_inject(path, json);
    free(json);
    free(path);
}


//Write all rules to the DB.
void write_db_rules() {

    struct rule * rule;

    list_for_each_entry(rule, &rules.list, list) {
        write_db_rule(rule);
    }
}


//Deletes the specified rule from the DB. Does not modify the internal rule list.
void delete_db_rule(char * rule_name) {

    char * path;
    path = safe_sprintf("%s/%s", DB_RULE_PATH, rule_name);
    db_rm(path);
    free(path);
}


//Deletes all rules in the DB. Does not modify the internal rule list.
void delete_db_rules() {

    db_rm(DB_RULE_PATH);
}


//Parses rules from the DB and adds them to the internal rule list.
bool parse_db_rules(struct parse_data * data) {

    yajl_val yajl;
    char ** rule_arr;
    char *json_all, *json_rule, *path;
    char *rule_name;
    char *name, *conditions, *actions, *undos;
    char err[1024];
    int num_rules, i, j;

    json_all = db_dump_path(DB_RULE_PATH);
    if (json == NULL) {
        xcpmd_log(LOG_WARNING, "Couldn't get rules from DB.");
        return false;
    }
    xcpmd_log(LOG_DEBUG, "Received json: %s", json_all);

    //There are no rules in the DB.
    if (*json_all == '\0' || !strncmp(json_all, "null", 4)) {
        xcpmd_log(LOG_DEBUG, "DB rules node is empty\n");
        free(json_all);
        return true;
    }

    yajl = yajl_tree_parse(json_all, err, sizeof(err));
    if (yajl == NULL) {
        xcpmd_log(LOG_WARNING, "Error parsing DB rules: %s", err);
        free(json_all);
        return false;
    }

    if (!YAJL_IS_OBJECT(yajl)) {
        xcpmd_log(LOG_WARNING, "Error parsing DB rules - %s is malformed (type %d)", DB_RULE_PATH, yajl->type);
        yajl_tree_free(yajl);
        free(json_all);
        return false;
    }

    num_rules = yajl->u.object.len;
    for (i=0; i < num_rules; ++i) {

        rule_name = (char *)yajl->u.object.keys[i];
        path = safe_sprintf("%s/%s", DB_RULE_PATH, rule_name);
        json_rule = db_dump_path(path);
        if (json_rule == NULL) {
            xcpmd_log(LOG_WARNING, "Failed to read DB rule at %s.", path);
            continue;
        }
        rule_arr = json_rule_to_parseable(rule_name, json_rule);
        free(json_rule);
        if (rule_arr == NULL) {
            xcpmd_log(LOG_WARNING, "Error parsing DB rule - rule %d is malformed", i);
            continue;
        }
        name = rule_arr[0];
        conditions = rule_arr[1];
        actions = rule_arr[2];
        undos = rule_arr[3];

        if (!parse_rule_persistent(data, name, conditions, actions, undos)) {
            xcpmd_log(LOG_WARNING, "Error reading DB rule %s - %s", rule_name, extract_parse_error(data));
        }

        for (j=0; j < 4; ++j)
            free(rule_arr[j]);
        free(rule_arr);
    }

    yajl_tree_free(yajl);
    free(json_all);

    return true;
}


//Allocates memory!
//Converts a JSON rule into a set of strings that the parser can handle.
//Returns an array of name, conditions, actions, and undos as parseable strings.
//Allocates memory for both the array and the strings themselves.
static char ** json_rule_to_parseable(char * name, char * json) {

    char *conditions, *actions, *undos;
    char ** string_array;
    int i, j, num_entries, num_args;
    char *str = NULL;
    char err[1024];
    yajl_val yajl, yconditions, yactions, yundos;
    yajl_val ycond, yact, yundo;
    yajl_val yinverted, ytype, yargs, yarg;

    const char * yajl_path[2] = { NULL, NULL };

    /*
     * A rule looks like this in the DB:
     *   rules:
     *       rule_name:
     *           conditions:
     *               0:
     *                   type: "whileUsingBatt"
     *                   is_inverted: "f"
     *                   args: ""
     *               1:
     *                   type: "whileBattLessThan"
     *                   is_inverted: "f"
     *                   args:
     *                       0: "50"
     *           actions:
     *               0:
     *                   type: "logString"
     *                   args:
     *                       0: "\"battery is less than 50%!\""
     *           undos: ""
     *
     * Whereas the parser understands rules in a four-string form, like this:
     *   name:       "rule_name"
     *   conditions: "whileUsingBatt() whileBattLessThan(50)"
     *   actions:    "logString(\"battery is less than 50%!\")"
     *   undos:      ""
     *
     * So we convert the DB structure into a YAJL tree, and walk it to get the
     * information we need.
     */

    //There's no guarantee that a DB node will be properly formatted, so a lot
    //of error checking is necessary.
    yajl = yajl_tree_parse(json, err, sizeof(err));
    if (yajl == NULL) {
        xcpmd_log(LOG_ERR, "Error parsing JSON: %s\n", err);
        return NULL;
    }

    //Check for bad JSON, but don't warn for a valid empty rule.
    if (YAJL_IS_STRING(yajl) && (!strncmp(yajl->u.string, "null", 4) || *(yajl->u.string) == '\0')) {
        goto free_yajl;
    }
    else if (!YAJL_IS_OBJECT(yajl)) {
        xcpmd_log(LOG_WARNING, "Error parsing JSON: rule is malformed");
        goto free_yajl;
    }

    //Get the rule's name.
    //name = clone_string(yajl->u.object.keys[i]);
    //yrule = yajl->u.object.values[i];

    //Get the conditions.
    yajl_path[0] = "conditions";
    yconditions = yajl_tree_get(yajl, yajl_path, yajl_t_any);
    if (!YAJL_IS_OBJECT(yconditions)) {
        xcpmd_log(LOG_WARNING, "Error parsing JSON: rule %s's conditions are malformed", name);
        goto free_yajl;
    }

    //Build the condition string, separating each condition with spaces.
    num_entries = yconditions->u.object.len;
    for (i = 0; i < num_entries; ++i) {

        ycond = yconditions->u.object.values[i];
        if (!YAJL_IS_OBJECT(ycond)) {
            xcpmd_log(LOG_WARNING, "Error parsing JSON: condition %i in rule %s is malformed", i, name);
            continue;
        }

        //Is the condition inverted?
        yajl_path[0] = "is_inverted";
        yinverted = yajl_tree_get(ycond, yajl_path, yajl_t_string);
        if (yinverted == NULL) {
            xcpmd_log(LOG_WARNING, "Error parsing JSON: condition %i in rule %s is missing is_inverted.", i, name);
            goto free_yajl;
        }
        if (!strcmp(yinverted->u.string, "true")) {
            safe_str_append(&str, "!");
        }

        //What's its type?
        yajl_path[0] = "type";
        ytype = yajl_tree_get(ycond, yajl_path, yajl_t_string);
        if (ytype == NULL) {
            xcpmd_log(LOG_WARNING, "Error parsing JSON: condition %i in rule %s is missing type.", i, name);
            goto free_yajl;
        }
        safe_str_append(&str, "%s(", YAJL_GET_STRING(ytype));

        //Get its arguments, if it has any.
        yajl_path[0] = "args";
        yargs = yajl_tree_get(ycond, yajl_path, yajl_t_any);
        if ((YAJL_IS_STRING(yargs) && *(YAJL_GET_STRING(yargs))) == '\0') {
            //Having no arguments is fine
        }
        else if (!YAJL_IS_OBJECT(yargs)) {
            xcpmd_log(LOG_WARNING, "Error parsing JSON: args of condition %s in rule %s is malformed", YAJL_GET_STRING(ytype), name);
            goto free_yajl;
        }
        else {
            num_args = yargs->u.object.len;
            for (j = 0; j < num_args; ++j) {

                yarg = yargs->u.object.values[j];

                if (!YAJL_IS_STRING(yarg)) {
                    xcpmd_log(LOG_WARNING, "Error parsing JSON: empty arg in condition %s in rule %s.\n", YAJL_GET_STRING(ytype), name);
                    goto free_yajl;
                }

                if (j == (num_args - 1))
                    safe_str_append(&str, "%s", YAJL_GET_STRING(yarg));
                else
                    safe_str_append(&str, "%s ", YAJL_GET_STRING(yarg));
            }
        }

        //Terminate with a space if this isn't the final condition.
        if (i == (num_entries - 1))
            safe_str_append(&str, ")");
        else
            safe_str_append(&str, ") ");
    }
    conditions = str;
    str = NULL;

    //Now do the same thing to get the action string.
    yajl_path[0] = "actions";
    yactions = yajl_tree_get(yajl, yajl_path, yajl_t_any);
    if (!YAJL_IS_OBJECT(yactions)) {
        xcpmd_log(LOG_WARNING, "Error parsing JSON: rule %s's actions are malformed", name);
        goto free_conditions;
    }

    //Glob those actions into a space-separated string.
    num_entries = yactions->u.object.len;
    for (i = 0; i < num_entries; ++i) {

        yact = yactions->u.object.values[i];
        if (!YAJL_IS_OBJECT(yact)) {
            xcpmd_log(LOG_WARNING, "Error parsing JSON: action %i in rule %s is malformed", i, name);
            continue;
        }

        //Get the action type.
        yajl_path[0] = "type";
        ytype = yajl_tree_get(yact, yajl_path, yajl_t_string);
        if (ytype == NULL) {
            xcpmd_log(LOG_WARNING, "Error parsing JSON: action %i in rule %s is missing type.", i, name);
            goto free_conditions;
        }
        safe_str_append(&str, "%s(", YAJL_GET_STRING(ytype));

        //Get its args, if it has any.
        yajl_path[0] = "args";
        yargs = yajl_tree_get(yact, yajl_path, yajl_t_any);
        if (YAJL_IS_STRING(yargs) && *(YAJL_GET_STRING(yargs)) == '\0') {
            //Having no args is fine.
        }
        else if (!YAJL_IS_OBJECT(yargs)) {
            xcpmd_log(LOG_WARNING, "Error parsing JSON: args of action %s in rule %s is malformed", YAJL_GET_STRING(ytype), name);
            goto free_conditions;
        }
        else {
            num_args = yargs->u.object.len;
            for (j = 0; j < num_args; ++j) {

                yarg = yargs->u.object.values[j];

                if (!YAJL_IS_STRING(yarg)) {
                    xcpmd_log(LOG_WARNING, "Error parsing JSON: empty arg in action %s in rule %s.\n", YAJL_GET_STRING(ytype), name);
                    goto free_conditions;
                }

                if (j == (num_args - 1))
                    safe_str_append(&str, "%s", YAJL_GET_STRING(yarg));
                else
                    safe_str_append(&str, "%s ", YAJL_GET_STRING(yarg));
            }
        }

        //Terminate with a space if this isn't the final action.
        if (i == (num_entries - 1))
            safe_str_append(&str, ")");
        else
            safe_str_append(&str, ") ");
    }
    actions = str;
    str = NULL;

    //Finally, build the undo actions string.
    yajl_path[0] = "undos";
    yundos = yajl_tree_get(yajl, yajl_path, yajl_t_any);
    if (YAJL_IS_STRING(yundos) && *(YAJL_GET_STRING(yundos)) == '\0') {
        //Undo actions are not required, so the undo string may be empty.
    }
    else if (!YAJL_IS_OBJECT(yundos)) {
        xcpmd_log(LOG_WARNING, "Error parsing JSON: rule %s's undos are malformed", name);
        goto free_actions;
    }
    else {
        //Undos, if they exist, are handled exactly like actions.
        num_entries = yundos->u.object.len;
        for (i = 0; i < num_entries; ++i) {

            yundo = yundos->u.object.values[i];
            if (!YAJL_IS_OBJECT(yundo)) {
                xcpmd_log(LOG_WARNING, "Error parsing JSON: undo %i in rule %s is malformed", i, name);
                continue;
            }

            yajl_path[0] = "type";
            ytype = yajl_tree_get(yundo, yajl_path, yajl_t_string);
            if (ytype == NULL) {
                xcpmd_log(LOG_WARNING, "Error parsing JSON: undo %i in rule %s is missing type.", i, name);
                goto free_actions;
            }
            safe_str_append(&str, "%s(", YAJL_GET_STRING(ytype));

            yajl_path[0] = "args";
            yargs = yajl_tree_get(yundo, yajl_path, yajl_t_any);
            if (YAJL_IS_STRING(yargs) && *(YAJL_GET_STRING(yargs)) == '\0') {
                //Having no args is fine.
            }
            else if (!YAJL_IS_OBJECT(yargs)) {
                xcpmd_log(LOG_WARNING, "Error parsing JSON: args of undo %s in rule %s is malformed", YAJL_GET_STRING(ytype), name);
                goto free_actions;
            }
            else {
                num_args = yargs->u.object.len;
                for (j = 0; j < num_args; ++j) {

                    yarg = yargs->u.object.values[j];

                    if (!YAJL_IS_STRING(yarg)) {
                        xcpmd_log(LOG_WARNING, "Error parsing JSON: empty arg in undo %s in rule %s.\n", YAJL_GET_STRING(ytype), name);
                        goto free_actions;
                    }

                    if (j == (num_args - 1))
                        safe_str_append(&str, "%s", YAJL_GET_STRING(yarg));
                    else
                        safe_str_append(&str, "%s ", YAJL_GET_STRING(yarg));
                }
            }

            //Terminate with a space if this isn't the final undo.
            if (i == (num_entries - 1))
                safe_str_append(&str, ")");
            else
                safe_str_append(&str, ") ");
        }
    }
    undos = str;

    //Finally, plunk the strings into a string array.
    string_array = (char **)malloc(4 * sizeof(char *));
    string_array[0] = clone_string(name);
    string_array[1] = conditions;
    string_array[2] = actions;
    string_array[3] = undos;

    //Clean up the YAJL tree.
    yajl_tree_free(yajl);

    return string_array;

//Failure modes - free anything allocated up to the point of failure.
free_actions:
    free(actions);
free_conditions:
    free(conditions);
free_yajl:

    if (str != NULL) {
        free(str);
    }

    yajl_tree_free(yajl);

    return NULL;
}


//Allocates memory!
//Converts a rule to a dynamically allocated json string.
//Elaborates all structure beneath "name", which is itself omitted.
//(Including "name" in the JSON string interferes with DB injection, and name
//is easy to retrieve from the rule anyway.)
static char * rule_to_json(struct rule * rule) {

    char index_string[32];
    char * arg_string, * bool_string;
    int index, arg_index;
    struct condition * cond;
    struct action * act;
    struct arg_node * arg;
    yajl_gen yajl;
    char * ret;
    size_t len;

    yajl = yajl_gen_alloc(NULL);
    if (yajl == NULL) {
        xcpmd_log(LOG_ERR, "Could not allocate memory!\n");
        return NULL;
    }

    //Add rule name
    //yajl_gen_string(yajl, (const unsigned char *)rule->id, strlen(rule->id));
    //yajl_gen_map_open(yajl);

    //Open the root.
    yajl_gen_map_open(yajl);

    //Add conditions.
    yajl_gen_string(yajl, (const unsigned char *)"conditions", strlen("conditions"));
    yajl_gen_map_open(yajl);

    index = 0;
    list_for_each_entry(cond, &rule->conditions.list, list) {
        snprintf(index_string, 32, "%d", index);
        yajl_gen_string(yajl, (const unsigned char *)index_string, strlen(index_string));
        yajl_gen_map_open(yajl);

        yajl_gen_string(yajl, (const unsigned char *)"type", strlen("type"));
        yajl_gen_string(yajl, (const unsigned char *)cond->type->name, strlen(cond->type->name));

        bool_string = cond->is_inverted ? "true" : "false";
        yajl_gen_string(yajl, (const unsigned char *)"is_inverted", strlen("is_inverted"));
        yajl_gen_string(yajl, (const unsigned char *)bool_string, strlen(bool_string));

        //Add the condition's arguments, if it has any.
        yajl_gen_string(yajl, (const unsigned char *)"args", strlen("args"));
        if (list_empty(&cond->args.list)) {
            yajl_gen_string(yajl, (const unsigned char *)"", 0);
        }
        else {
            yajl_gen_map_open(yajl);

            arg_index = 0;
            list_for_each_entry(arg, &cond->args.list, list) {
                snprintf(index_string, 32, "%d", arg_index);
                arg_string = arg_to_string(arg->type, arg->arg);
                yajl_gen_string(yajl, (const unsigned char *)index_string, strlen(index_string));
                yajl_gen_string(yajl, (const unsigned char *)arg_string, strlen(arg_string));
                free(arg_string);
                ++arg_index;
            }
            yajl_gen_map_close(yajl);
        }

        yajl_gen_map_close(yajl);
        ++index;
    }
    yajl_gen_map_close(yajl);


    //Add the rule's actions.
    yajl_gen_string(yajl, (const unsigned char *)"actions", strlen("actions"));
    yajl_gen_map_open(yajl);

    index = 0;
    list_for_each_entry(act, &rule->actions.list, list) {
        snprintf(index_string, 32, "%d", index);
        yajl_gen_string(yajl, (const unsigned char *)index_string, strlen(index_string));
        yajl_gen_map_open(yajl);

        yajl_gen_string(yajl, (const unsigned char *)"type", strlen("type"));
        yajl_gen_string(yajl, (const unsigned char *)act->type->name, strlen(act->type->name));

        //Add the action's arguments, if it has any.
        yajl_gen_string(yajl, (const unsigned char *)"args", strlen("args"));
        if (list_empty(&act->args.list)) {
            yajl_gen_string(yajl, (const unsigned char *)"", 0);
        }
        else {
            yajl_gen_map_open(yajl);

            arg_index = 0;
            list_for_each_entry(arg, &act->args.list, list) {
                snprintf(index_string, 32, "%d", arg_index);
                arg_string = arg_to_string(arg->type, arg->arg);
                yajl_gen_string(yajl, (const unsigned char *)index_string, strlen(index_string));
                yajl_gen_string(yajl, (const unsigned char *)arg_string, strlen(arg_string));
                free(arg_string);
                ++arg_index;
            }
            yajl_gen_map_close(yajl);
        }

        yajl_gen_map_close(yajl);
        ++index;
    }
    yajl_gen_map_close(yajl);


    //Add the undo actions, if any.
    yajl_gen_string(yajl, (const unsigned char *)"undos", strlen("undos"));
    if (list_empty(&rule->undos.list)) {
        yajl_gen_string(yajl, (const unsigned char *)"", 0);
    }
    else {
        yajl_gen_map_open(yajl);

        index = 0;
        list_for_each_entry(act, &rule->undos.list, list) {
            snprintf(index_string, 32, "%d", index);
            yajl_gen_string(yajl, (const unsigned char *)index_string, strlen(index_string));
            yajl_gen_map_open(yajl);

            yajl_gen_string(yajl, (const unsigned char *)"type", strlen("type"));
            yajl_gen_string(yajl, (const unsigned char *)act->type->name, strlen(act->type->name));

            //And arguments.
            yajl_gen_string(yajl, (const unsigned char *)"args", strlen("args"));
            if (list_empty(&act->args.list)) {
                yajl_gen_string(yajl, (const unsigned char *)"", 0);
            }
            else {
                yajl_gen_map_open(yajl);

                arg_index = 0;
                list_for_each_entry(arg, &act->args.list, list) {
                    snprintf(index_string, 32, "%d", arg_index);
                    arg_string = arg_to_string(arg->type, arg->arg);
                    yajl_gen_string(yajl, (const unsigned char *)index_string, strlen(index_string));
                    yajl_gen_string(yajl, (const unsigned char *)arg_string, strlen(arg_string));
                    free(arg_string);
                    ++arg_index;
                }
                yajl_gen_map_close(yajl);
            }
            yajl_gen_map_close(yajl);

            ++index;
        }
        yajl_gen_map_close(yajl);
    }
    yajl_gen_map_close(yajl);

    yajl_gen_get_buf(yajl, (const unsigned char **)&ret, &len);
    ret = clone_string(ret);

    yajl_gen_free(yajl);

    return ret;
}


//Allocates memory!
//Adds a variable, transparently caching it and writing back to the DB.
//If the variable already exists, and there are no type conflicts, its previous
//value will be overwritten.
//Modifies the internal cache.
//Writes error messages to *parse_error.
//May try to free existing strings in *parse_error--don't supply the address of
//a non-malloc'd string!
struct db_var * add_var(char * name, enum arg_type type, union arg_u value, char ** parse_error) {

    struct db_var * var = lookup_var(name);

    //A var with this name exists already. Check the type.
    if (var != NULL) {
        if (var->value.type != type) {
            safe_str_append(parse_error, "Attempted to overwrite variable %s, but aborted due to type mismatch (was %s, tried %s)",
                    name, arg_type_to_string((char)var->value.type), arg_type_to_string((char)type));
            return NULL;
        }
        if (!((var->value.type == ARG_STR && !strcmp(var->value.arg.str, value.str)) || !memcmp(&var->value.arg, &value, sizeof(union arg_u)))) {
            safe_str_append(parse_error, "Variable %s already exists--overwriting", name);
        }
        else {
            return var;
        }

        if(type == ARG_STR) {
            free(var->value.arg.str);
            var->value.arg.str = clone_string(value.str);
        }
        else {
            var->value.arg = value;
        }
    }
    else {
        var = cache_db_var(name, type, value);
    }

    if (var != NULL) {
        write_db_var(var->name, var->value.type, var->value.arg);
    }

    return var;
}


//Looks up a db_var based on its name, and caches it if it's not already in the
//cache. Returns null if the search fails.
struct db_var * lookup_var(char * name) {

    struct db_var * tmp_var, *found_var = NULL;
    struct arg_node tmp_arg;

    //Check if the var is cached.
    list_for_each_entry(tmp_var, &(db_vars.list), list) {
        if (strcmp(tmp_var->name, name) == 0) {
            found_var = tmp_var;
            break;
        }
    }

    //If not, look it up in the DB.
    if (found_var == NULL) {
        tmp_arg = get_db_var(name);

        //If it exists, add it to the cache.
        if (tmp_arg.type != ARG_NONE) {
            found_var = cache_db_var(name, tmp_arg.type, tmp_arg.arg);

            //get_db_var() allocs strings, so free.
            if (tmp_arg.type == ARG_STR) {
                free(tmp_arg.arg.str);
            }
        }
    }

    return found_var;
}


//Convenience function to skip the db_var struct.
struct arg_node * resolve_var(char * name) {

    struct db_var * var = lookup_var(name);

    if (var == NULL) {
        return NULL;
    }
    else {
        return &var->value;
    }
}


//Deletes a variable from both the DB and the internal cache.
int delete_var(char * name) {

    if (uncache_db_var(name)) {
        delete_db_var(name);
        return 1;
    }
    else {
        return 0;
    }
}


//Deletes all vars from both the DB and the internal cache.
void delete_vars() {

    delete_cached_vars();
    delete_db_vars();
}


//Allocates memory!
//Adds a variable to the cache. Allocates memory for both the db_var struct and
//any strings that must be copied.
static struct db_var * cache_db_var(char * name, enum arg_type type, union arg_u value) {

    struct db_var * var = (struct db_var *)malloc(sizeof(struct db_var));
    if (var == NULL) {
        xcpmd_log(LOG_ERR, "Failed to allocate memory\n");
        return NULL;
    }

    var->name = clone_string(name);
    var->value.type = type;
    if (type == ARG_STR) {
        var->value.arg.str = clone_string(value.str);
    }
    else {
        var->value.arg = value;
    }

    var->ref_count = 0;

    list_add_tail(&var->list, &db_vars.list);

    return var;
}


//Removes a variable from the internal cache. Does not modify the DB.
//Fails if the variable is required by any currently loaded rules.
static int uncache_db_var(char * name) {

    struct db_var *tmp_var, *found_var = NULL;

    list_for_each_entry(tmp_var, &(db_vars.list), list) {
        if (strcmp(tmp_var->name, name) == 0) {
            found_var = tmp_var;
            break;
        }
    }

    if (found_var == NULL) {
        return 0;
    }

    if (found_var->ref_count > 0) {
        xcpmd_log(LOG_WARNING, "Attempted to uncache %s, but it is currently in use in %d place%s",
                name, found_var->ref_count, found_var->ref_count == 1 ? "" : "s");
        return 0;
    }

    list_del(&found_var->list);
    if (found_var->value.type == ARG_STR) {
        free(found_var->value.arg.str);
    }
    free(found_var->name);
    free(found_var);
    return 1;
}


//Clears the entire var cache, regardless of refcounts. Does not modify the DB.
void delete_cached_vars() {

    struct list_head *posi, *i;
    struct db_var * tmp_var;

    //Clean up all cached db_vars.
    list_for_each_safe(posi, i, &db_vars.list) {
        tmp_var = list_entry(posi, struct db_var, list);
        list_del(posi);
        free(tmp_var->name);
        if (tmp_var->value.type == ARG_STR) {
            free(tmp_var->value.arg.str);
        }
        free(tmp_var);
    }
}
