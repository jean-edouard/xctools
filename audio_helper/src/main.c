//
// Copyright (c) 2015 Assured Information Security, Inc
//
// Dates Modified:
//  - 4/8/2015: Initial commit
//    Rian Quinn <quinnr@ainfosec.com>
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#include "unittest.h"
#include "openxtalsa.h"
#include "openxtdebug.h"
#include "openxtvmaudio.h"
#include "openxtmixerctl.h"

#include <unistd.h>
#include <getopt.h>

void help(int argc, char *argv[])
{
    openxt_info("Usage: %s <options> [commands]\n", argv[0]);
    openxt_info("Available Options:\n");
    openxt_info("    -h, --help             this help\n");
    openxt_info("    -c, --card N           select the card\n");
    openxt_info("    -D, --device N         select the device, default 'default'\n");
    openxt_info("\n");
    openxt_info("Available Commands:\n");
    openxt_info("    <stubdomid>            start audio backend for guest with stubdomid=<stubdomid>\n");
    openxt_info("    unittest               run audio backend unittest\n");
    openxt_info("    scontrols              show all mixer simple controls\n");
    openxt_info("    scontents              show contents of all mixer simple controls (default command)\n");
    openxt_info("    sset sID P [on/off]    enable/disable and set contents for one mixer simple control\n");
    openxt_info("    sget sID               get contents for one mixer simple control\n");
    exit(0);
}

int parse_options(int argc, char *argv[])
{
    // Define the available options
    static const struct option long_option[] =
    {
        {"help", 0, NULL, 'h'},
        {"card", 1, NULL, 'c'},
        {"device", 1, NULL, 'D'},
        {NULL, 0, NULL, 0},
    };

    // Get the options.
    while (1) {

        int c;
        int ret;

        // Get the next argument
        if ((c = getopt_long(argc, argv, "hc:D:", long_option, NULL)) < 0)
            break;

        switch (c) {
            case 'h':
                help(argc, argv);
                break;

            case 'c':
                ret = openxt_alsa_set_card(snd_card_get_index(optarg));
                openxt_assert(ret == 0, ret);
                break;

            case 'D':
                ret = openxt_alsa_set_device(optarg);
                openxt_assert(ret == 0, ret);
                break;

            default:
                openxt_error("Invalid switch or option needs an argument.\n");
        }
    }

    if (argc - optind <= 0) {

        // Default
        return openxt_mixer_ctl_scontents(argc, argv);

    } else {

        // Help Menu
        if (strncmp(argv[optind], "help", 4) == 0) help(argc, argv);

        // Unit Test
        if (strncmp(argv[optind], "unittest", 8) == 0) return openxt_unittest(argc, argv);

        // Amixer commands
        if (strncmp(argv[optind], "scontrols", 9) == 0) return openxt_mixer_ctl_scontrols(argc, argv);
        if (strncmp(argv[optind], "scontents", 9) == 0) return openxt_mixer_ctl_scontents(argc, argv);
        if (strncmp(argv[optind], "sset", 4) == 0) return openxt_mixer_ctl_sset(argc, argv);
        if (strncmp(argv[optind], "sget", 4) == 0) return openxt_mixer_ctl_sget(argc, argv);

        // VM Backend
        return openxt_vmaudio(argc, argv);
    }
}

int main(int argc, char *argv[])
{
    int ret;
    openxt_debug_init();

    ret = parse_options(argc, argv);

    openxt_debug_fini();
    return ret;
}
