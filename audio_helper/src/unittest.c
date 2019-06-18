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

#include "openxtargo.h"
#include "openxtalsa.h"
#include "openxtdebug.h"

////////////////////////////////////////////////////////////////////////////////
// Global Variables                                                           //
////////////////////////////////////////////////////////////////////////////////

int32_t pass = 0;
int32_t fail = 0;

////////////////////////////////////////////////////////////////////////////////
// Tests                                                                      //
////////////////////////////////////////////////////////////////////////////////

typedef struct TestPacket {

    int32_t data1;
    int32_t data2;

} TestPacket;

void test_argo(void)
{
    ArgoConnection *client = NULL;
    ArgoConnection *server = NULL;

    // Packets
    ArgoPacket snd_packet;
    ArgoPacket rcv_packet;
    TestPacket *snd_packet_body = NULL;
    TestPacket *rcv_packet_body = NULL;

    // Start from zero.
    memset(&snd_packet, 0, sizeof(snd_packet));
    memset(&rcv_packet, 0, sizeof(rcv_packet));

    // TODO: The following still needs testing:
    //
    // - I currently am not testing invalid arguments to openxt_argo_open. This
    //   one is hard as Argo doesn't really check things on it's own

    // Make sure the validate function works
    UT_CHECK(openxt_argo_validate(sizeof(TestPacket)) == true);
    UT_CHECK(openxt_argo_validate(ARGO_MAX_PACKET_BODY_SIZE * 2) == false);

    // Make sure that we hit the correct errors
    UT_CHECK(openxt_argo_isconnected(NULL) == false);
    UT_CHECK(openxt_argo_isconnected(NULL) == false);

    // We should not be connected
    UT_CHECK(openxt_argo_isconnected(client) == false);
    UT_CHECK(openxt_argo_isconnected(server) == false);

    // Valid setup
    UT_CHECK((client = openxt_argo_open(XEN_ARGO_PORT_NONE, XEN_ARGO_DOMID_ANY, 5001, 0)) != NULL);
    UT_CHECK((server = openxt_argo_open(5001, XEN_ARGO_DOMID_ANY, XEN_ARGO_PORT_NONE, 0)) != NULL);

    // Make sure that we are connected
    UT_CHECK(openxt_argo_isconnected(client) == true);
    UT_CHECK(openxt_argo_isconnected(server) == true);

    // Make sure that we hit the correct errors
    UT_CHECK(openxt_argo_close(NULL) == -EINVAL);
    UT_CHECK(openxt_argo_close(NULL) == -EINVAL);

    // Make sure that we can close the connection
    UT_CHECK(openxt_argo_close(client) == 0);
    UT_CHECK(openxt_argo_close(server) == 0);

    // Setup again
    UT_CHECK((client = openxt_argo_open(XEN_ARGO_PORT_NONE, XEN_ARGO_DOMID_ANY, 5001, 0)) != NULL);
    UT_CHECK((server = openxt_argo_open(5001, XEN_ARGO_DOMID_ANY, XEN_ARGO_PORT_NONE, 0)) != NULL);

    // Make sure that we hit the correct errors
    UT_CHECK(openxt_argo_set_opcode(NULL, 0) == -EINVAL);
    UT_CHECK(openxt_argo_set_length(NULL, 0) == -EINVAL);
    UT_CHECK(openxt_argo_set_length(&snd_packet, ARGO_MAX_PACKET_BODY_SIZE * 2) == -EOVERFLOW);

    // Set the length and opcode
    UT_CHECK(openxt_argo_set_opcode(&snd_packet, 5) == 0);
    UT_CHECK(openxt_argo_set_opcode(&rcv_packet, 5) == 0);
    UT_CHECK(openxt_argo_set_length(&snd_packet, sizeof(TestPacket)) == 0);
    UT_CHECK(openxt_argo_set_length(&rcv_packet, sizeof(TestPacket)) == 0);

    // Make sure that we hit the correct errors
    UT_CHECK(openxt_argo_get_opcode(NULL) == -EINVAL);
    UT_CHECK(openxt_argo_get_length(NULL) == -EINVAL);

    // Set the length and opcode
    UT_CHECK(openxt_argo_get_opcode(&snd_packet) == 5);
    UT_CHECK(openxt_argo_get_opcode(&rcv_packet) == 5);
    UT_CHECK(openxt_argo_get_length(&snd_packet) == sizeof(TestPacket));
    UT_CHECK(openxt_argo_get_length(&rcv_packet) == sizeof(TestPacket));

    // Make sure that we hit the correct errors
    UT_CHECK((snd_packet_body = openxt_argo_get_body(NULL)) == NULL);
    UT_CHECK((rcv_packet_body = openxt_argo_get_body(NULL)) == NULL);

    // Make sure that we get valid pointers
    UT_CHECK((snd_packet_body = openxt_argo_get_body(&snd_packet)) != NULL);
    UT_CHECK((rcv_packet_body = openxt_argo_get_body(&rcv_packet)) != NULL);

    // Put data into the packets
    if (snd_packet_body && rcv_packet_body)
    {
        snd_packet_body->data1 = 1;
        snd_packet_body->data2 = 2;

        // Make sure that we hit the correct errors
        UT_CHECK(openxt_argo_send(NULL, &snd_packet) == -EINVAL);
        UT_CHECK(openxt_argo_recv(NULL, &rcv_packet) == -EINVAL);
        UT_CHECK(openxt_argo_send(client, NULL) == -EINVAL);
        UT_CHECK(openxt_argo_recv(server, NULL) == -EINVAL);

        // Mess up the connection
        UT_CHECK(openxt_argo_close_internal(client) == 0);
        UT_CHECK(openxt_argo_close_internal(server) == 0);

        // Make sure that we hit the correct errors
        UT_CHECK(openxt_argo_send(client, &snd_packet) == -ENODEV);
        UT_CHECK(openxt_argo_recv(server, &rcv_packet) == -ENODEV);

        // Mess up the length
        snd_packet.header.length = ARGO_MAX_PACKET_BODY_SIZE * 2;
        rcv_packet.header.length = ARGO_MAX_PACKET_BODY_SIZE * 2;

        // Make sure that we hit the correct errors
        UT_CHECK(openxt_argo_send(client, &snd_packet) == -EOVERFLOW);

        // Clean things up
        UT_CHECK(openxt_argo_close(client) == 0);
        UT_CHECK(openxt_argo_close(server) == 0);
        UT_CHECK((client = openxt_argo_open(XEN_ARGO_PORT_NONE, XEN_ARGO_DOMID_ANY, 5001, 0)) != NULL);
        UT_CHECK((server = openxt_argo_open(5001, XEN_ARGO_DOMID_ANY, XEN_ARGO_PORT_NONE, 0)) != NULL);
        UT_CHECK(openxt_argo_set_length(&snd_packet, sizeof(TestPacket)) == 0);
        UT_CHECK(openxt_argo_set_length(&rcv_packet, sizeof(TestPacket)) == 0);

        // Validate that you can send / recv correctly.
        UT_CHECK(openxt_argo_send(client, &snd_packet) == sizeof(TestPacket));
        UT_CHECK(openxt_argo_recv(server, &rcv_packet) == sizeof(TestPacket));

        // Validate the result
        UT_CHECK(rcv_packet_body->data1 == 1);
        UT_CHECK(rcv_packet_body->data2 == 2);
    }
}

void test_alsa(void)
{
    int ret;
    char buffer[256];
    Settings *playback_settings = NULL;
    Settings *capture_settings = NULL;

    // Validate improper card #
    ret = openxt_alsa_set_card(-1);
    UT_CHECK(ret == -EINVAL);

    // Validate improper card #
    ret = openxt_alsa_set_card(32);
    UT_CHECK(ret == -EINVAL);

    // Validate proper usage of the API (assumes 0 is a valid card #)
    ret = openxt_alsa_set_card(0);
    UT_CHECK(ret == 0);

    // Validate improper device name
    ret = openxt_alsa_set_device(NULL);
    UT_CHECK(ret == -EINVAL);

    // Validate improper device name
    ret = openxt_alsa_set_device(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    UT_CHECK(ret == -EINVAL);

    // Validate proper usage of the API
    ret = openxt_alsa_set_device("default");
    UT_CHECK(ret == 0);

    // Validate improper creation of the settings variable.
    ret = openxt_alsa_create(NULL);
    UT_CHECK(ret == -EINVAL);

    // Make sure that we can only create the setting variable once
    ret = openxt_alsa_create(&playback_settings);
    UT_CHECK(ret == 0);
    ret = openxt_alsa_create(&playback_settings);
    UT_CHECK(ret == -EINVAL);

    // Make sure that we can destroy the setting variable.
    ret = openxt_alsa_destroy(playback_settings);
    UT_CHECK(ret == 0);
    playback_settings = NULL;

    // Need to create the settings variable for the rest of the tests.
    ret = openxt_alsa_create(&playback_settings);
    UT_CHECK(ret == 0);
    ret = openxt_alsa_create(&capture_settings);
    UT_CHECK(ret == 0);

    // Sanity check
    openxt_checkp(playback_settings);
    openxt_checkp(capture_settings);

    // Setup the playback_settings variable.
    playback_settings->fmt = SND_PCM_FORMAT_S16_LE;
    playback_settings->freq = 44100;
    playback_settings->mode = 0;
    playback_settings->stream = SND_PCM_STREAM_PLAYBACK;
    playback_settings->nchannels = 2;
    playback_settings->sample_size = sizeof(uint32_t);
    playback_settings->selement_index = 0;
    snprintf(playback_settings->pcm_name, sizeof(playback_settings->pcm_name), getenv("ALSA_DEVICE"));
    snprintf(playback_settings->selement_name, sizeof(playback_settings->selement_name), "Master");

    // Setup the capture_settings variable.
    capture_settings->fmt = SND_PCM_FORMAT_S16_LE;
    capture_settings->freq = 44100;
    capture_settings->mode = SND_PCM_NONBLOCK;
    capture_settings->stream = SND_PCM_STREAM_CAPTURE;
    capture_settings->nchannels = 2;
    capture_settings->sample_size = sizeof(uint32_t);
    capture_settings->selement_index = 0;
    snprintf(capture_settings->pcm_name, sizeof(capture_settings->pcm_name), getenv("ALSA_DEVICE"));
    snprintf(capture_settings->selement_name, sizeof(capture_settings->selement_name), "Capture");

    // Validate improper use of the init function
    ret = openxt_alsa_init(NULL);
    UT_CHECK(ret == -EINVAL);

    // Init ALSA (and validate repeating)
    ret = openxt_alsa_init(playback_settings);
    UT_CHECK(ret == 0);
    ret = openxt_alsa_init(playback_settings);
    UT_CHECK(ret == 0);

    // Validate improper use of the fini function
    ret = openxt_alsa_fini(NULL);
    UT_CHECK(ret == -EINVAL);

    // Properly close the settings.
    ret = openxt_alsa_fini(playback_settings);
    UT_CHECK(ret == 0);

    // Validate improper use of the prepare function
    ret = openxt_alsa_prepare(NULL);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the prepare function
    ret = openxt_alsa_prepare(playback_settings);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the drop function
    ret = openxt_alsa_drop(NULL);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the drop function
    ret = openxt_alsa_drop(playback_settings);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the start function
    ret = openxt_alsa_start(NULL);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the start function
    ret = openxt_alsa_start(playback_settings);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the get available function
    ret = openxt_alsa_get_available(NULL);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the get available function
    ret = openxt_alsa_get_available(playback_settings);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the writei function
    ret = openxt_alsa_writei(NULL, buffer, 10, sizeof(buffer));
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the writei function
    ret = openxt_alsa_writei(playback_settings, NULL, 10, sizeof(buffer));
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the writei function
    ret = openxt_alsa_writei(playback_settings, buffer, 1000000, sizeof(buffer));
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the writei function
    ret = openxt_alsa_writei(playback_settings, buffer, 10, sizeof(buffer));
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the readi function
    ret = openxt_alsa_readi(NULL, buffer, 10, sizeof(buffer));
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the readi function
    ret = openxt_alsa_readi(playback_settings, NULL, 10, sizeof(buffer));
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the readi function
    ret = openxt_alsa_readi(playback_settings, buffer, 1000000, sizeof(buffer));
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the readi function
    ret = openxt_alsa_readi(playback_settings, buffer, 10, sizeof(buffer));
    UT_CHECK(ret == -EINVAL);

    // Init ALSA
    ret = openxt_alsa_init(playback_settings);
    UT_CHECK(ret == 0);
    ret = openxt_alsa_init(capture_settings);
    UT_CHECK(ret == 0);

    // Validate improper deletion of the settings variable.
    ret = openxt_alsa_destroy(playback_settings);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the init function
    ret = openxt_alsa_mixer_init(NULL);
    UT_CHECK(ret == -EINVAL);

    // Init ALSA (and validate repeating)
    ret = openxt_alsa_mixer_init(playback_settings);
    UT_CHECK(ret == 0);
    ret = openxt_alsa_mixer_init(playback_settings);
    UT_CHECK(ret == 0);

    // Validate improper use of the fini function
    ret = openxt_alsa_mixer_fini(NULL);
    UT_CHECK(ret == -EINVAL);

    // Properly close the settings.
    ret = openxt_alsa_mixer_fini(playback_settings);
    UT_CHECK(ret == 0);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_print_selement(NULL);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_print_selement(playback_settings);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_print_selements(NULL);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_print_selements(playback_settings);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_sget(NULL);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_sget(playback_settings);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_sset_enum(NULL, "test");
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_sset_enum(playback_settings, NULL);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_sset_enum(playback_settings, "test");
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_sset_volume(NULL, 0);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_sset_volume(playback_settings, -1);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_sset_volume(playback_settings, 101);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_sset_volume(playback_settings, 0);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_sset_switch(NULL, 0);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_mixer_sset_switch(playback_settings, 0);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_percentage(NULL, 0);
    UT_CHECK(ret == -EINVAL);

    // Validate improper use of the mixer API
    ret = openxt_alsa_percentage(playback_settings, 0);
    UT_CHECK(ret == -EINVAL);

    // Init ALSA
    ret = openxt_alsa_mixer_init(playback_settings);
    UT_CHECK(ret == 0);

    // Validate proper use of the mixer API
    ret = openxt_alsa_mixer_print_selements(playback_settings);
    UT_CHECK(ret == 0);

    // Validate proper use of the mixer API
    ret = openxt_alsa_mixer_sget(playback_settings);
    UT_CHECK(ret == 0);

    // Validate proper use of the mixer API
    ret = openxt_alsa_mixer_print_selement(playback_settings);
    UT_CHECK(ret == 0);

    // Validate proper use of the mixer API
    ret = openxt_alsa_mixer_sset_volume(playback_settings, 100);
    UT_CHECK(ret == 0);

    // Validate proper use of the mixer API
    ret = openxt_alsa_mixer_sset_switch(playback_settings, 1);
    UT_CHECK(ret == 0);

    // Validate improper use of the mixer API
    ret = openxt_alsa_percentage(playback_settings, 10);
    UT_CHECK(ret >= 0);

    // Validate improper use of the mixer API
    ret = openxt_alsa_remove_pcm(NULL);
    UT_CHECK(ret == -EINVAL);

    // Close the mixer
    ret = openxt_alsa_mixer_fini(playback_settings);
    UT_CHECK(ret == 0);

    // Done with ALSA
    ret = openxt_alsa_fini(playback_settings);
    UT_CHECK(ret == 0);
    ret = openxt_alsa_fini(capture_settings);
    UT_CHECK(ret == 0);

    // Cleanup
    ret = openxt_alsa_destroy(playback_settings);
    UT_CHECK(ret == 0);
    playback_settings = NULL;
    ret = openxt_alsa_destroy(capture_settings);
    UT_CHECK(ret == 0);
    capture_settings = NULL;
}

///
/// ALSA_DEVICE="hw:1" ./audio_helper unittest test_capture > /storage/disks/test.snd
///
void test_capture(void)
{
    int ret;
    int avail;
    int nread;
    int32_t buffer[1024];
    Settings *capture_settings = NULL;

    ret = openxt_alsa_create(&capture_settings);
    UT_CHECK(ret == 0);

    // Sanity check
    openxt_checkp(capture_settings);

    // Setup the capture_settings variable.
    capture_settings->fmt = SND_PCM_FORMAT_S16_LE;
    capture_settings->freq = 44100;
    capture_settings->mode = SND_PCM_NONBLOCK;
    capture_settings->stream = SND_PCM_STREAM_CAPTURE;
    capture_settings->nchannels = 2;
    capture_settings->sample_size = sizeof(uint32_t);
    capture_settings->selement_index = 0;
    snprintf(capture_settings->pcm_name, sizeof(capture_settings->pcm_name), getenv("ALSA_DEVICE"));
    snprintf(capture_settings->selement_name, sizeof(capture_settings->selement_name), "Capture");

    // Initialize the Capture device.
    ret = openxt_alsa_init(capture_settings);
    UT_CHECK(ret == 0);

    // Start the capture device.
    ret = openxt_alsa_prepare(capture_settings);
    UT_CHECK(ret == 0);
    ret = openxt_alsa_start(capture_settings);
    UT_CHECK(ret == 0);

    // Ready!!!
    openxt_debug("\nCapture Started:\n");

    // The read/write API used a blocking/non-blocking hybrid. Basically ALSA is
    // open in blocking mode, but we ask ALSA how many samples are available prior
    // to using the readi / write functions, which should cause the function
    // to never block. Because of this, we need to provide in our test, a sleep
    // so that we can mimic QEMU, as it basically does the same thing.
    while (1) {

        usleep(250);

        // Get the data.
        nread = openxt_alsa_readi(capture_settings, buffer, 1024, sizeof(buffer));

        // Make sure there is something to process
        if (nread <= 0)
            continue;

        // Write the data.
        write(1, buffer, nread * sizeof(int32_t));
    }
}

///
/// ALSA_DEVICE="hw:1" ./audio_helper unittest test_playback < /storage/disks/test.snd
///
void test_playback(void)
{
    int ret;
    int avail;
    int nread;
    int32_t buffer[1024];
    Settings *playback_settings = NULL;

    ret = openxt_alsa_create(&playback_settings);
    UT_CHECK(ret == 0);

    // Sanity check
    openxt_checkp(playback_settings);

    // Setup the playback_settings variable.
    playback_settings->fmt = SND_PCM_FORMAT_S16_LE;
    playback_settings->freq = 44100;
    playback_settings->mode = 0;
    playback_settings->stream = SND_PCM_STREAM_PLAYBACK;
    playback_settings->nchannels = 2;
    playback_settings->sample_size = sizeof(uint32_t);
    playback_settings->selement_index = 0;
    snprintf(playback_settings->pcm_name, sizeof(playback_settings->pcm_name), getenv("ALSA_DEVICE"));
    snprintf(playback_settings->selement_name, sizeof(playback_settings->selement_name), "Master");

    // Initialize the Capture device.
    ret = openxt_alsa_init(playback_settings);
    UT_CHECK(ret == 0);

    // Start the capture device.
    ret = openxt_alsa_prepare(playback_settings);
    UT_CHECK(ret == 0);

    // Ready!!!
    openxt_debug("\nPlayback Started:\n");

    // The read/write API used a blocking/non-blocking hybrid. Basically ALSA is
    // open in blocking mode, but we ask ALSA how many samples are available prior
    // to using the readi / write functions, which should cause the function
    // to never block. Because of this, we need to provide in our test, a sleep
    // so that we can mimic QEMU, as it basically does the same thing.
    while (1) {

        usleep(250);

        // Get the available number of samples.
        avail = openxt_alsa_get_available(playback_settings);
        avail = min(avail, 1024);

        // Make sure that there is something to process
        if (avail == 0)
            continue;

        // Write the data.
        nread = read(0, buffer, avail * sizeof(int32_t));

        // Stop once complete
        if (nread <= 0)
            break;

        // Get the data.
        openxt_alsa_writei(playback_settings, buffer, avail, sizeof(buffer));
    }
}

////////////////////////////////////////////////////////////////////////////////
// Support                                                                    //
////////////////////////////////////////////////////////////////////////////////

int openxt_unittest(int argc, char *argv[])
{
    int i;

    // Make sure that we have the right number of arguments.
    if (argc < 3){
        openxt_info("wrong syntax: expecting ALSA_DEVICE=\"hw:<#>\" %s unittest [tests]\n", argv[0]);
        openxt_info("available tests:\n");
        openxt_info("    - test_argo\n");
        openxt_info("    - test_alsa\n");
        openxt_info("    - test_capture\n");
        openxt_info("    - test_playback\n");
        return -EINVAL;
    }

    openxt_debug_set_enabled(false);

    // Header
    openxt_debug("--------------------------------------------\n");
    openxt_debug("- Unit Tests                               -\n");
    openxt_debug("--------------------------------------------\n");
    openxt_debug("\n");

    // Tests
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "test_argo") == 0) test_argo();
        if (strcmp(argv[i], "test_alsa") == 0) test_alsa();
        if (strcmp(argv[i], "test_capture") == 0) test_capture();
        if (strcmp(argv[i], "test_playback") == 0) test_playback();
    }

    // Footer
    openxt_debug("\n");
    openxt_debug("\n");
    openxt_debug("passed: %d\n", pass);
    openxt_debug("failed: %d\n", fail);
    openxt_debug("\n");

    openxt_debug_set_enabled(true);

    // Done
    return 0;
}
