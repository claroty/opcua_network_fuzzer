import struct
from construct import *
from raw_messages_opcua import get_raw_open_session_messages


########################################################################################################################
#################################                         OPC TYPES            #########################################
########################################################################################################################
from datetime import datetime, timedelta, tzinfo
from calendar import timegm

EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000

ZERO = timedelta(0)
HOUR = timedelta(hours=1)


class UTC(tzinfo):
    """UTC"""

    def utcoffset(self, dt):
        return ZERO

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return ZERO


utc = UTC()


def dt_to_filetime(dt):
    if (dt.tzinfo is None) or (dt.tzinfo.utcoffset(dt) is None):
        dt = dt.replace(tzinfo=utc)
    return EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * HUNDREDS_OF_NANOSECONDS)


def get_real_time(dt):
    us = dt / 10
    return datetime(1601, 1, 1) + timedelta(microseconds=us)


OPC_STRING = Struct(
    "str_length" / Int32ul,
    "str" / If(this.str_length != 0xffffffff,
               PaddedString(this.str_length, "utf8"))
)

OPC_BYTES = Struct(
    "bytes_length" / Int32ul,
    "bytes" / IfThenElse(this.bytes_length == 0xffffffff, Bytes(0), Bytes(this.bytes_length)))

ARRAY_OF_STRINGS = Struct(
    "array_size" / Int32ul,
    "string_array" / If(this.array_size != 0xffffffff,
                        Array(this.array_size, OPC_STRING))
)
########################################################################################################################
#################################                     NAMESPACE MASKS          #########################################
########################################################################################################################
SIZE_LENGTH = Struct(
    "namespace_index" / Int16ul,
    "item" / Int32ul
)
OPAQUE = Struct(
    "namespace_index" / Int16ul,
    "item" / OPC_BYTES
)
FOUR_BYTE = Struct(
    "namespace_index" / Int8ul,
    "item" / Int16ul
)

GUID = Struct(
    "namespace_index" / Int16ul,
    "item" / Bytes(16)
)
ONLY_ITEM = Struct(
    "namespace_index" / Pass,
    "item" / Int8ul
)

TEST_ITEM = Struct(
    "namespace_index" / Int16ul,
    "item" / OPC_STRING
)

SECURITY_TOKEN = Struct(
    "channel_id" / Int32ul,
    "token_id" / Int32ul,
    "token_timestamp" / Int64ul,
    "token_revised_lifetime" / Int32ul
)

OBJECT = Struct(
    "encoding_mask" / BitStruct(
        "has_namespace_uri" / Flag,
        "has_server_index" / Flag,
        "unk1" / Flag,
        "unk2" / Flag,
        "arbitrary_length" / Nibble
    ),
    "identifier_numeric" / Switch(this.encoding_mask.arbitrary_length,
                                  {0: ONLY_ITEM,
                                   1: FOUR_BYTE,
                                   3: TEST_ITEM,
                                   2: SIZE_LENGTH,
                                   4: GUID,
                                   5: OPAQUE}
                                  )
)

OBJECT_HEADER = Struct(
    "main_object" / OBJECT,
    "timestamp" / Int64ul,
    "request_handle" / Int32ul,
    # bitmap
    "return_diagnostics" / Int32ul,
    "audit_entry_id" / OPC_STRING,
    "timeout_hint" / Int32ul,
    "extension_object" / OBJECT,
)
########################################################################################################################
########################################                OPEN             ###############################################
########################################################################################################################
OPEN_SECURE_CHANNEL_REQUEST = Struct(
    "authentication_token" / OBJECT_HEADER,
    "encoding_mask" / Int8ul,
    "client_protocol_version" / Int32ul,
    "security_request_type" / Int32ul,
    "message_security_mode" / Int32ul,
    "unk" / Int32ul,
    "has_nonce" / Peek(GreedyBytes),

    "client_nonce" / If(lambda x: len(x.has_nonce) > 4,  Int8ul),
    "requested_lifetime" / Int32ul
)

OPEN_SECURE_CHANNEL_RESPONSE = Struct(
    # OpenSecureChannelResponse:
    "timestamp" / Int64ul,
    "request_handle" / Int32ul,
    "service_results" / Int32ul,
    "service_diagnostics" / Int8ul,
    "string_table_size" / Int32ul,
    "string_array" / If(this.string_table_size != 0xffffffff,
                        Array(lambda x: x.string_table_size, OPC_STRING)),
    "additional_header_type_id" / Int16ul,
    "additional_header_encoding_mask" / Int8ul,
    "server_protocol_version" / Int32ul,
    "security_token" / SECURITY_TOKEN,
    "server_nonce" / OPC_STRING
)
########################################################################################################################
########################################                CREATE           ###############################################
########################################################################################################################
CREATE_SESSION_REQUEST = Struct(
    "authenticationobject" / OBJECT_HEADER,
    "binary_or_xml" / Int8ul,
    "application_uri" / OPC_STRING,
    "product_uri" / OPC_STRING,
    "encoding_mask" / Int8ul,
    "client_name" / OPC_STRING,
    "application_type" / Int32ul,
    "gateway_server_uri" / OPC_STRING,
    "discovery_profile_uri" / OPC_STRING,
    "num_of_discovery_urls" / Int32ul,
    "discovery_urls" / If(this.num_of_discovery_urls != 0xffffffff,
                          Array(lambda x: x.num_of_discovery_urls, OPC_STRING)),
    "server_uri" / OPC_STRING,
    "enspoint_url" / OPC_STRING,
    "session_name" / OPC_STRING,
    "client_nonce_size" / Int32ul,
    "client_nonce" / Bytes(this.client_nonce_size),
    "client_certificate" / OPC_STRING,
    # "uukn" / Int32ul,
    "request_session_timeout" / Float64l,
    "max_response_message_size" / Int32ul,
)

CREATE_SESSION_RESPONSE = Struct(
    "timestamp" / Int64ul,
    "request_handler" / Int32ul,
    "service_results" / Int32ul,
    "service_diagnostics_encoding_mask" / Int8ul,
    "string_array" / ARRAY_OF_STRINGS,
    "ext_obj" / OBJECT,
    "encoding_mask" / Int8ul,
    "session_id" / OBJECT,
    "auth_token" / OBJECT
)
ACTIVATE_REQUEST = Struct(
    "auth_token" / OBJECT_HEADER,
    "encoding_mask" / Int8ul,
    "algo" / OPC_STRING,
    "signature" / OPC_BYTES,
    "client_cert_array_size" / Int32ul,
    "client_cert_array" / If(this.client_cert_array_size !=
                             0xffffffff, Array(this.client_cert_array_size, OPC_BYTES)),
    "local_ids_array_size" / Int32ul,
    "local_ids_array" / If(this.client_cert_array_size !=
                           0xffffffff, Array(this.local_ids_array_size, OPC_STRING)),
    "user_id_token" / OBJECT,
    "encoding_mask2" / Int8ul,
    "unk" / Int32ul,
    "policy_id" / OPC_STRING,
    "sign_algo" / OPC_STRING,
    "sign_sig" / OPC_BYTES
)
########################################################################################################################
########################################            ENCODABLES           ###############################################
########################################################################################################################
ENCODEABLE_OBJECT = Struct(
    "node_id_encoding_mask" / Int8ul,
    "node_id_namespace_index" / Int8ul,
    "node_id_identifier_numeric" / Int16ul,
    "object" / Switch(this.node_id_identifier_numeric,
                      {
                          446: OPEN_SECURE_CHANNEL_REQUEST,
                          449: OPEN_SECURE_CHANNEL_RESPONSE,
                          461: CREATE_SESSION_REQUEST,
                          464: CREATE_SESSION_RESPONSE,
                          467: ACTIVATE_REQUEST,
                      })
)

OPEN_REQUEST = Struct(
    "secure_channel_id" / Int32ul,
    # http://opcfoundation.org/UA/SecurityPolicy#None
    "securit_policy_uri" / OPC_STRING,
    # ffffff
    "sender_certificate" / OPC_STRING,
    "reciever_certificate_thumbprint" / OPC_STRING,
    "sequence_number" / Int32ul,
    "request_id_number" / Int32ul,

    # encodable_object:
    "object" / ENCODEABLE_OBJECT
)

HELLO_REQUEST = Struct(
    "version" / Int32ul,
    "receive_buffer_size" / Int32ul,
    "send_buffer_size" / Int32ul,
    "max_message_size" / Int32ul,
    "max_chunk_count" / Int32ul
)
########################################################################################################################
########################################            HEADERS              ###############################################
########################################################################################################################
OPEN = Struct(
    "secure_channel_id" / Int32ul,
    # http://opcfoundation.org/UA/SecurityPolicy#None
    "securit_policy_uri" / OPC_STRING,
    # ffffff
    "sender_certificate" / OPC_STRING,
    "reciever_certificate_thumbprint" / OPC_STRING,
    "sequence_number" / Int32ul,
    "request_id_number" / Int32ul,

    # encodable_object:
    "object" / ENCODEABLE_OBJECT
)

MSG = Struct(
    "secure_channel_id" / Int32ul,
    "security_token_id" / Int32ul,
    "security_sequence_number" / Int32ul,
    "security_request_idr" / Int32ul,
    "object" / ENCODEABLE_OBJECT
)
HELLO = Struct(
    "version" / Int32ul,
    "receive_buffer_size" / Int32ul,
    "send_buffer_size" / Int32ul,
    "max_message_size" / Int32ul,
    "max_chunk_count" / Int32ul
)

HELLO_MSG = Struct(
    "hello_header" / HELLO,
    # opc.tcp://ip:port
    "endpoint_url" / OPC_STRING)

OPCUA_MESSAGE = Struct(
    "message_type" / PaddedString(3, "utf8"),
    "chunk_type" / PaddedString(1, "utf8"),
    "message_size" / Int32ul,
    "opc_data" / Switch(this.message_type,
                        {"HEL": HELLO_MSG,
                         "ACK": HELLO,
                         "OPN": OPEN,
                         "MSG": MSG}),
    "leftover" / GreedyBytes
)


def my_recv(s, prev=b""):
    header = s.recv(8)
    tmp_resp = b""
    message_size = struct.unpack("I", header[4:8])[0]
    header_type = header[3:4]

    payload_size_left = message_size - 8
    while payload_size_left > 0:
        response = s.recv(max(1024, payload_size_left))
        tmp_resp += response
        payload_size_left -= len(response)

    if header_type == b"F":
        return header[0:3] + b"F" + struct.pack("I", len(prev + tmp_resp)) + prev + tmp_resp
    else:
        return my_recv(s, prev + tmp_resp)


def send_recv(s, msg):
    msg_length = len(msg)
    msg = bytearray(msg)
    msg[4:8] = struct.pack("I", msg_length)
    s.send(msg)
    return my_recv(s)


def send_recv_parse(s, msg, construct_obj=OPCUA_MESSAGE):
    res = send_recv(s, msg)
    return construct_obj.parse(res)


def recvall(sock, n):
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data


def create_session(sock, program_type, session_timeout=360000, open_timestamp=None, requested_lifetime=279520, session_name=None):
    hel_raw, opn_raw, create_raw, activate_raw = get_raw_open_session_messages(
        program_type)
    # HEL message
    send_recv(sock, hel_raw)

    # OPN message
    if open_timestamp or requested_lifetime:
        opn_parsed = OPCUA_MESSAGE.parse(opn_raw)

        if open_timestamp:
            opn_parsed.opc_data.object.object.authentication_token.timestamp = open_timestamp
        elif requested_lifetime:
            opn_parsed.opc_data.object.object.requested_lifetime = requested_lifetime
        open_msg = OPCUA_MESSAGE.build(opn_parsed)
    else:
        open_msg = opn_raw

    open_resp = send_recv_parse(sock, open_msg)

    secure_channel_id = open_resp.opc_data.secure_channel_id
    secure_token_id = open_resp.opc_data.object.object.security_token.token_id
    # we take this from request which make the this field be server dependent
    sequence = OPCUA_MESSAGE.parse(opn_raw).opc_data.sequence_number

    # Create
    create_session_parsed = OPCUA_MESSAGE.parse(create_raw)
    create_session_parsed.opc_data.secure_channel_id = secure_channel_id
    if program_type == "ignition":
        create_session_parsed.opc_data.security_token_id = secure_token_id
    if session_timeout:
        create_session_parsed.opc_data.object.object.request_session_timeout = session_timeout
    if session_name:
        create_session_parsed.opc_data.object.object.session_name.str = session_name
        create_session_parsed.opc_data.object.object.session_name.str_length = len(
            session_name)
    create_session_built = OPCUA_MESSAGE.build(create_session_parsed)
    create_resp = send_recv_parse(sock, create_session_built)

    auth_id = create_resp.opc_data.object.object.auth_token

    # Activate
    activate_session_parsed = OPCUA_MESSAGE.parse(activate_raw)
    if program_type == "ignition":
        activate_session_parsed.opc_data.security_token_id = secure_token_id
    activate_session_parsed.opc_data.secure_channel_id = secure_channel_id
    activate_session_parsed.opc_data.object.object.auth_token.main_object = auth_id
    activate_session_build = OPCUA_MESSAGE.build(activate_session_parsed)

    send_recv(sock, activate_session_build)

    return secure_channel_id, auth_id, sequence, secure_token_id
