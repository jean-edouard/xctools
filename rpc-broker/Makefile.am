AM_CFLAGS = -g -Wall -lpthread \
	$(DBUS_CFLAGS) $(V4V_CFLAGS) $(LIBWEBSOCKETS_CFLAGS) \
    $(JSON_C_CFLAGS) $(LIBXML_CFLAGS) 

sbin_PROGRAMS = rpc-broker
rpc_broker_SOURCES = \
    src/rpc-broker.c \
    src/websockets.c \
    src/policy.c \
    src/dbus.c \
    src/msg.c \
    src/json.c \
    src/signature.c \
    src/rpc-broker.h

noinst_HEADERS = src/rpc-broker.h

rpc_broker_LDADD = \
    $(DBUS_LIBS) \
    $(LIBV4V_LIBS) \
    $(LIBWEBSOCKETS_LIBS) \
    $(JSON_C_LIBS) \
    $(LIBXML_LIBS) \
    $(XENSTORE_LIBS) \
    -luv
