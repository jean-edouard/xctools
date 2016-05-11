divert(-1)
# rpc_definitions.m4
#
# Macros:
#   DEFINE_MESSAGE(id, name, format...)
#   Define a message type with the given format.
#   The message ID is fixed by the user and not generated so the
#   comunicating ends can remain backward compatible with older
#   versions of the library.
#
#   DEFINE_IN_RPC_NO_RETURN(in_message_type)
#   Define an asynchronous, inbound (dm to service) RPC using
#   in_message_type as a previously defined input message type.
#   The caller does not expect a reply message.
#
#   DEFINE_IN_RPC_WITH_RETURN(in_message_type, out_message_type)
#   Define a synchronous, inbound (dm to service) RPC using
#   in_message_type as a previously defined input message type.
#   The caller expects a reply of the out_message_type message type.
#
#   DEFINE_OUT_RPC(out_message_type)
#   Define an asynchronous, outbound (service to dm) RPC using
#   out_message_type as a previously defined output message type.
#   The RPC is directed to a unique connected client.
#
#   DEFINE_BROADCAST_RPC(out_message_type)
#   Define an asynchronous, outbound (service to dm) RPC using
#   out_message_type as a previously defined output message type.
#   The RPC is broadcasted to all connected clients.
#
include(rpcgen.m4)

# Surfman
DEFINE_MESSAGE(0, display_resize, uint8_t DisplayID,
                               uint16_t width,
                               uint16_t height,
                               uint32_t linesize,
                               uint64_t lfb_addr,
                               uint8_t lfb_traceable,
                               FramebufferFormat format,
                               uint32_t fb_offset)
DEFINE_MESSAGE(1, display_get_info, uint8_t DisplayID)
DEFINE_MESSAGE(2, display_info, uint8_t DisplayID,
                             uint16_t max_xres,
                             uint16_t max_yres,
                             uint16_t align)
DEFINE_MESSAGE(8, empty_reply)

DEFINE_IN_RPC_WITH_RETURN(display_resize, empty_reply)
DEFINE_IN_RPC_WITH_RETURN(display_get_info, display_info)

# Input

DEFINE_MESSAGE(16, switcher_abs, int32_t enabled)
DEFINE_MESSAGE(17, switcher_pvm_domid, uint32_t domid, int32_t slot)
DEFINE_MESSAGE(18, switcher_domid, uint32_t domid, int32_t slot)
DEFINE_MESSAGE(19, switcher_leds, int32_t led_code)
DEFINE_MESSAGE(20, switcher_shutdown, int32_t reason)

DEFINE_MESSAGE(21, dom0_input_event, uint16_t type,
                                     uint16_t code,
                                     int32_t value)
DEFINE_MESSAGE(24, input_config_reset, uint8_t slot)
DEFINE_MESSAGE(25, input_config, InputConfig c)
DEFINE_MESSAGE(26, input_wakeup)

DEFINE_IN_RPC_NO_RETURN(switcher_abs)
DEFINE_IN_RPC_NO_RETURN(switcher_pvm_domid)
DEFINE_IN_RPC_NO_RETURN(switcher_domid)
DEFINE_IN_RPC_NO_RETURN(switcher_leds)
DEFINE_IN_RPC_NO_RETURN(switcher_shutdown)
DEFINE_OUT_RPC(dom0_input_event)
DEFINE_OUT_RPC(input_config)
DEFINE_OUT_RPC(input_config_reset)
DEFINE_OUT_RPC(input_wakeup)

# Common message
DEFINE_MESSAGE(23, device_model_ready)
DEFINE_OUT_RPC(device_model_ready) # Indicate the service is ready to emulate the new domain

divert(0)dnl
