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

#include "openxtargo.h"
#include "openxtalsa.h"
#include "openxtdebug.h"
#include "openxtpackets.h"
#include "openxtvmaudio.h"

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Global Data / Structures                                                                            //
/////////////////////////////////////////////////////////////////////////////////////////////////////////

Settings *playback_settings = NULL;
Settings *capture_settings = NULL;

// Global Argo Packets
ArgoPacket snd_packet;
ArgoPacket rcv_packet;

// GLobal Argo Connection
ArgoConnection *conn = NULL;

// Global Argo Packet Playback Bodies
OpenXTPlaybackPacket *playback_packet = NULL;
OpenXTPlaybackInitAckPacket *playback_init_ack_packet = NULL;
OpenXTPlaybackSetVolumePacket *playback_set_volume_packet = NULL;
OpenXTPlaybackGetAvailableAckPacket *playback_get_available_ack_packet = NULL;

// Global Argo Packet Capture Bodies
OpenXTCapturePacket *capture_packet = NULL;
OpenXTCaptureAckPacket *capture_ack_packet = NULL;
OpenXTCaptureInitAckPacket *capture_init_ack_packet = NULL;
OpenXTCaptureGetAvailableAckPacket *capture_get_available_ack_packet = NULL;

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Playback Functions                                                                                  //
/////////////////////////////////////////////////////////////////////////////////////////////////////////

///
///
///
/// @param
/// @return -EINVAL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
static int openxt_process_playback(void)
{
    int ret;

    ret = openxt_alsa_writei(playback_settings,
                             playback_packet->samples,
                             playback_packet->num_samples,
                             MAX_PCM_BUFFER_SIZE);
    openxt_assert_ret(ret == playback_packet->num_samples, ret, -EPIPE);

    return 0;
}

///
///
///
/// @param
/// @return -EINVAL
///         -EINVAL
///         negative error code on failure
///         0 on success
///
static int openxt_process_playback_init(void)
{
    int ret;
    int valid = 1;

    // Set the valid bit
    valid &= (openxt_alsa_init(playback_settings) == 0) ? 1 : 0;
    valid &= (openxt_alsa_mixer_init(playback_settings) == 0) ? 1 : 0;

    // Store the resulting valid state for later use.
    playback_settings->valid = valid;

    // Setup the ack packet
    ret = openxt_argo_set_opcode(&snd_packet, OPENXT_PLAYBACK_INIT_ACK);
    openxt_assert_ret(ret == 0, ret, ret);
    ret = openxt_argo_set_length(&snd_packet, sizeof(OpenXTPlaybackInitAckPacket));
    openxt_assert_ret(ret == 0, ret, ret);

    // Setup the ack body that will be sent back to QEMU. Specifically we need to
    // tell QEMU what frequency we are actually running at, as well as
    // if ALSA was actually configured
    playback_init_ack_packet->fmt = playback_settings->fmt;
    playback_init_ack_packet->freq = playback_settings->freq;
    playback_init_ack_packet->valid = playback_settings->valid;
    playback_init_ack_packet->nchannels = playback_settings->nchannels;

    // Send the ack.
    ret = openxt_argo_send(conn, &snd_packet);
    openxt_assert_ret(ret == sizeof(OpenXTPlaybackInitAckPacket), ret, ret);

    // Success
    return 0;
}

static int openxt_process_playback_fini(void)
{
    openxt_alsa_mixer_fini(playback_settings);
    openxt_alsa_fini(playback_settings);

    // No validation code on fini. If there is an error there really isn't
    // much you can do about it and you want as much of the code closing
    // down safely as possible

    return 0;
}

static int openxt_process_playback_set_volume(void)
{
    int ret;

    ret = openxt_alsa_mixer_sget(playback_settings);
    openxt_assert_ret(ret == 0, ret, ret);
    ret = openxt_alsa_mixer_sset_volume(playback_settings, playback_set_volume_packet->vol);
    openxt_assert_ret(ret == 0, ret, ret);
    ret = openxt_alsa_mixer_sset_switch(playback_settings, playback_set_volume_packet->enabled);
    openxt_assert_ret(ret == 0, ret, ret);

    return 0;
}

static int openxt_process_playback_enable_voice(void)
{
    int ret;

    ret = openxt_alsa_prepare(playback_settings);
    openxt_assert_ret(ret == 0, ret, ret);

    return 0;
}

static int openxt_process_playback_disable_voice(void)
{
    int ret;

    ret = openxt_alsa_drop(playback_settings);
    openxt_assert_ret(ret == 0, ret, ret);

    return 0;
}

static int openxt_process_playback_get_available(void)
{
    int ret;

    // Setup the packet.
    ret = openxt_argo_set_opcode(&snd_packet, OPENXT_PLAYBACK_GET_AVAILABLE_ACK);
    openxt_assert_ret(ret == 0, ret, ret);
    ret = openxt_argo_set_length(&snd_packet, sizeof(OpenXTPlaybackGetAvailableAckPacket));
    openxt_assert_ret(ret == 0, ret, ret);

    // Fill in the packet's contents.
    playback_get_available_ack_packet->available = openxt_alsa_get_available(playback_settings);

    // Send the packet.
    ret = openxt_argo_send(conn, &snd_packet);
    openxt_assert_ret(ret == sizeof(OpenXTPlaybackGetAvailableAckPacket), ret, ret);

    // Success
    return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Playback Functions                                                                                  //
/////////////////////////////////////////////////////////////////////////////////////////////////////////

static int openxt_process_capture(void)
{
    int ret;
    int nread;

    // Fill in the packet with the samples from the sound card.
    nread = openxt_alsa_readi(capture_settings,
                              capture_ack_packet->samples,
                              capture_packet->num_samples,
                              MAX_PCM_BUFFER_SIZE);
    openxt_assert_ret(nread >= 0, nread, nread);

    // Setup the packet.
    ret = openxt_argo_set_opcode(&snd_packet, OPENXT_CAPTURE_ACK);
    openxt_assert_ret(ret == 0, ret, ret);
    ret = openxt_argo_set_length(&snd_packet, CAPTURE_ACK_PACKET_LENGTH(nread));
    openxt_assert_ret(ret == 0, ret, ret);

    capture_ack_packet->num_samples = nread;

    // Send the packet.
    ret = openxt_argo_send(conn, &snd_packet);
    openxt_assert_ret(ret == CAPTURE_ACK_PACKET_LENGTH(nread), ret, ret);

    // Success
    return 0;
}

static int openxt_process_capture_init(void)
{
    int ret;
    int valid = 1;

    // Set the valid bit
    valid &= (openxt_alsa_init(capture_settings) == 0) ? 1 : 0;

    // Store the resulting valid state for later use.
    capture_settings->valid = valid;

    // Setup the ack packet
    ret = openxt_argo_set_opcode(&snd_packet, OPENXT_CAPTURE_INIT_ACK);
    openxt_assert_ret(ret == 0, ret, ret);
    ret = openxt_argo_set_length(&snd_packet, sizeof(OpenXTCaptureInitAckPacket));
    openxt_assert_ret(ret == 0, ret, ret);

    // Setup the ack body that will be sent back to QEMU. Specifically we need to
    // tell QEMU what frequency we are actually running at, as well as
    // if ALSA was actually configured
    capture_init_ack_packet->fmt = capture_settings->fmt;
    capture_init_ack_packet->freq = capture_settings->freq;
    capture_init_ack_packet->valid = capture_settings->valid;
    capture_init_ack_packet->nchannels = capture_settings->nchannels;

    // Send the ack.
    ret = openxt_argo_send(conn, &snd_packet);
    openxt_assert_ret(ret == sizeof(OpenXTCaptureInitAckPacket), ret, ret);

    // Success
    return 0;
}

static int openxt_process_capture_fini(void)
{
    openxt_alsa_fini(capture_settings);

    // No validation code on fini. If there is an error there really isn't
    // much you can do about it and you want as much of the code closing
    // down safely as possible

    return 0;
}

static int openxt_process_capture_enable_voice(void)
{
    int ret;

    ret = openxt_alsa_prepare(capture_settings);
    openxt_assert_ret(ret == 0, ret, ret);
    ret = openxt_alsa_start(capture_settings);
    openxt_assert_ret(ret == 0, ret, ret);

    return 0;
}

static int openxt_process_capture_disable_voice(void)
{
    int ret;

    ret = openxt_alsa_drop(capture_settings);
    openxt_assert_ret(ret == 0, ret, ret);

    return 0;
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////
// Main                                                                                                //
/////////////////////////////////////////////////////////////////////////////////////////////////////////

int openxt_vmaudio(int argc, char *argv[])
{
    // Local variables
    int ret;
    int32_t opcode = 0;
    int32_t stubdomid = 0;

    // Make sure that we have the right number of arguments.
    if (argc != 2) {
        openxt_info("wrong syntax: expecting %s <stubdomid>\n", argv[0]);
        return -EINVAL;
    }

    // Get the stubdomain's id
    stubdomid = atoi(argv[1]);

    // Create the settings structures.
    ret = openxt_alsa_create(&playback_settings);
    openxt_assert_ret(ret == 0, ret, ret);
    ret = openxt_alsa_create(&capture_settings);
    openxt_assert_ret(ret == 0, ret, ret);

    // Setup the playback ALSA settings. Note that because the format is
    // 16 bit signed little endian with 2 channels, the total sample size per
    // channel is 32 bits.
    playback_settings->fmt = SND_PCM_FORMAT_S16_LE;
    playback_settings->freq = 44100;
    playback_settings->mode = 0;
    playback_settings->stream = SND_PCM_STREAM_PLAYBACK;
    playback_settings->nchannels = 2;
    playback_settings->sample_size = sizeof(uint32_t);
    playback_settings->selement_index = 0;

    // Setup the capture ALSA settings. Note that because the format is
    // 16 bit signed little endian with 2 channels, the total sample size per
    // channel is 32 bits.
    capture_settings->fmt = SND_PCM_FORMAT_S16_LE;
    capture_settings->freq = 44100;
    capture_settings->mode = SND_PCM_NONBLOCK;
    capture_settings->stream = SND_PCM_STREAM_CAPTURE;
    capture_settings->nchannels = 2;
    capture_settings->sample_size = sizeof(uint32_t);
    capture_settings->selement_index = 0;

    // Set the ALSA device names. These device names exist inside of the
    // ALSA configuration file, so we need to make sure that they match. To
    // see where these are being set, look at the audio_helper_start script.
    snprintf(capture_settings->pcm_name, MAX_NAME_LENGTH, "dsnoop0");
    snprintf(playback_settings->pcm_name, MAX_NAME_LENGTH, "plug:vm-%d", stubdomid - 1);
    snprintf(playback_settings->selement_name, MAX_NAME_LENGTH, "vm-%d", stubdomid - 1);

    // Cleanup memory (safety)
    memset(&snd_packet, 0, sizeof(ArgoPacket));
    memset(&rcv_packet, 0, sizeof(ArgoPacket));

    // Pointer checks
    openxt_checkp(playback_packet = openxt_argo_get_body(&rcv_packet), -EINVAL);
    openxt_checkp(playback_init_ack_packet = openxt_argo_get_body(&snd_packet), -EINVAL);
    openxt_checkp(playback_set_volume_packet = openxt_argo_get_body(&rcv_packet), -EINVAL);
    openxt_checkp(playback_get_available_ack_packet = openxt_argo_get_body(&snd_packet), -EINVAL);

    // Pointer checks
    openxt_checkp(capture_packet = openxt_argo_get_body(&rcv_packet), -EINVAL);
    openxt_checkp(capture_ack_packet = openxt_argo_get_body(&snd_packet), -EINVAL);
    openxt_checkp(capture_init_ack_packet = openxt_argo_get_body(&snd_packet), -EINVAL);
    openxt_checkp(capture_get_available_ack_packet = openxt_argo_get_body(&snd_packet), -EINVAL);

    // Size checks
    openxt_assert(openxt_argo_validate(sizeof(OpenXTPlaybackPacket)) == true, -EINVAL);
    openxt_assert(openxt_argo_validate(sizeof(OpenXTPlaybackInitAckPacket)) == true, -EINVAL);
    openxt_assert(openxt_argo_validate(sizeof(OpenXTPlaybackSetVolumePacket)) == true, -EINVAL);
    openxt_assert(openxt_argo_validate(sizeof(OpenXTPlaybackGetAvailableAckPacket)) == true, -EINVAL);

    // Size checks
    openxt_assert(openxt_argo_validate(sizeof(OpenXTCapturePacket)) == true, -EINVAL);
    openxt_assert(openxt_argo_validate(sizeof(OpenXTCaptureAckPacket)) == true, -EINVAL);
    openxt_assert(openxt_argo_validate(sizeof(OpenXTCaptureInitAckPacket)) == true, -EINVAL);
    openxt_assert(openxt_argo_validate(sizeof(OpenXTCaptureGetAvailableAckPacket)) == true, -EINVAL);

    // Setup Argo
    conn = openxt_argo_open(OPENXT_AUDIO_PORT, XEN_ARGO_DOMID_ANY, XEN_ARGO_PORT_NONE, stubdomid);
    openxt_assert_ret(conn != NULL, conn, -EINVAL);

    // Process incoming commands from QEMU in the stubdomain. Once we get a
    // "fini" command from QEMU, we know that we can stop executing.
    while (opcode != OPENXT_FINI) {

        // Wait for a packet to come in from Argo
        ret = openxt_argo_recv(conn, &rcv_packet);
        openxt_assert_ret(ret >= 0, ret, ret);

        // Process the packet
        switch(opcode = openxt_argo_get_opcode(&rcv_packet)) {

            case OPENXT_FINI:
                break;

            case OPENXT_PLAYBACK:
                ret = openxt_process_playback();
                openxt_assert_ret(ret == 0, ret, ret);
                break;

            case OPENXT_PLAYBACK_INIT:
                ret = openxt_process_playback_init();
                openxt_assert_ret(ret == 0, ret, ret);
                break;

            case OPENXT_PLAYBACK_FINI:
                ret = openxt_process_playback_fini();
                openxt_assert_ret(ret == 0, ret, ret);
                break;

            case OPENXT_PLAYBACK_SET_VOLUME:
                ret = openxt_process_playback_set_volume();
                openxt_assert_ret(ret == 0, ret, ret);
                break;

            case OPENXT_PLAYBACK_ENABLE_VOICE:
                ret = openxt_process_playback_enable_voice();
                openxt_assert_ret(ret == 0, ret, ret);
                break;

            case OPENXT_PLAYBACK_DISABLE_VOICE:
                ret = openxt_process_playback_disable_voice();
                openxt_assert_ret(ret == 0, ret, ret);
                break;

            case OPENXT_PLAYBACK_GET_AVAILABLE:
                ret = openxt_process_playback_get_available();
                openxt_assert_ret(ret == 0, ret, ret);
                break;

            case OPENXT_CAPTURE:
                ret = openxt_process_capture();
                openxt_assert_ret(ret == 0, ret, ret);
                break;

            case OPENXT_CAPTURE_INIT:
                ret = openxt_process_capture_init();
                openxt_assert_ret(ret == 0, ret, ret);
                break;

            case OPENXT_CAPTURE_FINI:
                ret = openxt_process_capture_fini();
                openxt_assert_ret(ret == 0, ret, ret);
                break;

            case OPENXT_CAPTURE_ENABLE_VOICE:
                ret = openxt_process_capture_enable_voice();
                openxt_assert_ret(ret == 0, ret, ret);
                break;

            case OPENXT_CAPTURE_DISABLE_VOICE:
                ret = openxt_process_capture_disable_voice();
                openxt_assert_ret(ret == 0, ret, ret);
                break;

            default:
                openxt_warn("unknown packet opcode: %d\n", opcode);
                exit(-EINVAL);
        }
    }

    // Remove the PCM
    openxt_alsa_remove_pcm(playback_settings);

    // Safely shutdown ALSA mixer
    openxt_alsa_mixer_fini(playback_settings);

    // Safely shutdown ALSA
    openxt_alsa_fini(playback_settings);
    openxt_alsa_fini(capture_settings);

    // Cleanup
    openxt_alsa_destroy(playback_settings);
    openxt_alsa_destroy(capture_settings);

    // Done
    return 0;
}
