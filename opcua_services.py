from opcua_utils import *
from uuid import uuid4
from struct import pack

HEADER_SIZE = 24

##############################################
# Groups
##############################################

# For tests
TEST_GROUP = [pack("<I", i) for i in range(1, 3)]

# Browse direction within browse request
BROWSE_DIRECTION = [pack("<I", i) for i in range(1, 5)]

# Look for AttributeIds in python-opcua + 2 (for fun)
ATTRIBUTE_ID = [pack("<I", i) for i in range(1, 30)]

BOOLEAN = [b'\x01', b'\x00']

RANGE_AMOUNT_OF_ELEMENTS = [
    pack("<I", i) for i in range(1, 1000, 100)]

# NodeClass (opcua-python)
NODE_CLASS = [pack("<I", i) for i in [0, 1, 2, 4, 8, 16, 32, 64, 128]]

# Encoding mask another aditional for fun
ENCODING_MASK = [b'\x00', b'\x01', b'\x02', b'\x04']

# TimestampsToReturn (opcua-python) and additional for fun
TIMESTAMP_TO_RETURN = [pack("<I", i) for i in range(6)]


# this will take a while but it runs only once
BYTE_RANGE = [pack("B", i) for i in range(0, 0xff, 10)] + [b'\xff']
WORD_RANGE = [pack("<H", i) for i in range(0, 0xffff, 1000)] + [b'\xff\xff']
DWORD_RANGE = [pack("<I", i) for i in range(
    0, 0xffffffff, 1000000)] + [b'\xff\xff\xff\xff']
QWORD_RANGE = [pack("<Q", i) for i in range(
    0, 0xffffffffffffffff, 1000000000000000)] + [b'\xff\xff\xff\xff\xff\xff\xff\xff']

##############################################
# Common blocks
##############################################


def header_common_block():
    with s_block("header"):
        s_string("MSG", fuzzable=False, name="msg_type")
        s_string("F", fuzzable=False, name="chunk_type")
        # add HEADER_SIZE (offset) to size so it will include the header's size
        s_size("opcua_service", offset=HEADER_SIZE, length=4, fuzzable=False,
               name="message_size")
        # Updated per session
        s_static(b'\x00', name="secure_channel_id")
        s_dword(1, fuzzable=False, name="security_token_id")
        # Updated per session
        s_static(b'\x00', name="security_sequence_id")
        # This request will be fourth in the session
        s_dword(4, fuzzable=False, name="security_request_id")


def node_id_common_block(block_name, index=1):
    with s_block(block_name):
        # TODO Support bit fields
        s_static(b'\x00\x00', name=f"previously_generated_node_id_{index}")


def request_header_common_block(to_fuzz=True):
    with s_block("request_header"):
        with s_block("authentication_token"):
            s_static(b'\x00', name="auth_id")
        s_bytes(b'\x86\xca\x5a\xa5\xa4\xd0\xd7\x01',
                size=8, fuzzable=to_fuzz, name="time_stamp")
        s_dword(3, fuzzable=False, name="request_handle")
        with s_block("return_diagnostics"):
            s_dword(0, fuzzable=to_fuzz, name="return_diagnostics_bit_fields")
        opcua_string("audit_enty_id")
        s_dword(0, fuzzable=False, name="timeout_hint")
        extension_object_common_block("additional_header")


def qualified_name_common_block(name):
    with s_block(name):
        s_word(0, fuzzable=True, name="namespace_index")
        opcua_string("name")


def extension_object_common_block(name):
    elem_id = uuid4()
    with s_block(name):
        node_id_common_block("type_id")
        s_group(values=ENCODING_MASK, name=f"encoding_mask_{elem_id}")
        with s_block("body", dep=f"encoding_mask_{elem_id}", dep_value=b'\x00', dep_compare="!="):
            opcua_bytes("body_item")


##############################################
# OPCUA Common Types (complex types that aren't blocks by themselves)
##############################################

def opcua_string(name, to_fuzz=True):
    elem_id = uuid4()
    if to_fuzz:
        s_size(block_name=f"{name}_{elem_id}", fuzzable=False, length=4,
               math=lambda x: -1 if x == 0 else x, name="size_of_string")
        with s_block(f"{name}_{elem_id}"):
            s_random(str.encode('opcua'), max_length=15,
                     name="randomized_string")
    else:
        s_static(b'\xff\xff\xff\xff', name=name)


def opcua_bytes(name, to_fuzz=True):
    elem_id = uuid4()
    if to_fuzz:
        s_size(block_name=f"{name}_{elem_id}", fuzzable=False, length=4,
               math=lambda x: -1 if x == 0 else x, name="size_of_bytes")
        with s_block(f"{name}_{elem_id}"):
            s_random(b'\xDE\xAD\xBE\xEF', max_length=15,
                     name="randomized_bytes")
    else:
        s_static(b'\xff\xff\xff\xff', name=name)


def attribute_id():
    s_group(values=ATTRIBUTE_ID, name="attribute_id")


##############################################
# Callbacks
##############################################

def build_read_request_packet(name):
    s_initialize(name)
    header_common_block()
    with s_block("opcua_service"):
        with s_block("type_id"):
            # this one should remain constant
            s_byte(0x01, fuzzable=False, name="encoding_mask")
            s_byte(0x00, fuzzable=False, name="namespace_index")
            s_static(pack("<H", 631), name="identifier_numeric")
        with s_block("read_request"):
            request_header_common_block(to_fuzz=False)
            s_bytes(b'\x00\x00\x00\x00\x00\x00\x00\x40',
                    size=8, fuzzable=False, name="max_age")
            s_group(values=TIMESTAMP_TO_RETURN, name="timestamp_to_return")
            with s_block("nodes_to_read"):
                s_group(values=RANGE_AMOUNT_OF_ELEMENTS,
                        name="array_size")
                with s_block("read_value_id", dep="array_size", dep_value=pack("I", 0), dep_compare="!="):
                    node_id_common_block("node_id")
                    attribute_id()
                    opcua_string("index_range")
                    qualified_name_common_block("data_encoding")
                s_opcua_repeat(
                    "read_value_id", bound_block_repetitions="array_size", name="read_value_id_repeater")


def build_browse_request_packet(name):
    s_initialize(name)
    header_common_block()
    with s_block("opcua_service"):
        with s_block("type_id"):
            # this one should remain constant
            s_byte(0x01, fuzzable=False, name="encoding_mask")
            s_byte(0x00, fuzzable=False, name="namespace_index")
            s_static(pack("<H", 527), name="identifier_numeric")
        with s_block("browse_request"):
            request_header_common_block(to_fuzz=False)
            with s_block("view"):
                node_id_common_block("view_id")
                s_group(values=QWORD_RANGE, name="timestamp")
                s_group(values=DWORD_RANGE, name="view_version")
            s_group(values=DWORD_RANGE, name="request_max_references_per_node")
            with s_block("nodes_to_browse"):
                s_group(values=RANGE_AMOUNT_OF_ELEMENTS,
                        name="array_size")
                with s_block("browse_description", dep="array_size", dep_value=pack("I", 0), dep_compare="!="):
                    node_id_common_block("node_id")
                    s_group(values=BROWSE_DIRECTION, name="browse_direction")
                    node_id_common_block("reference_type_id")
                    s_group(values=BOOLEAN, name="include_sub_types")
                    s_group(values=DWORD_RANGE, name="node_class_mask")
                    s_group(values=DWORD_RANGE, name="result_mask")
                s_opcua_repeat(
                    "browse_description", bound_block_repetitions="array_size", name="browse_description_repeater")


def build_create_subscription_request_packet(name):
    s_initialize(name)
    header_common_block()
    with s_block("opcua_service"):
        with s_block("type_id"):
            # this one should remain constant
            s_byte(0x01, fuzzable=False, name="encoding_mask")
            s_byte(0x00, fuzzable=False, name="namespace_index")
            s_static(pack("<H", 787), name="identifier_numeric")
        with s_block("create_subscription_request"):
            request_header_common_block(to_fuzz=False)
            s_group(values=QWORD_RANGE, name="requested_publishing_interval")
            s_group(values=DWORD_RANGE, name="RequestedLifetimeCount")
            s_group(values=DWORD_RANGE, name="RequestedMaxKeepAliveCount")
            s_group(values=DWORD_RANGE, name="MaxNotificationsPerPublish")
            s_group(values=BOOLEAN, name="PublishingEnabled")
            s_group(values=BYTE_RANGE, name="Priority")


def build_browse_next_request_packet(name):
    s_initialize(name)
    header_common_block()
    with s_block("opcua_service"):
        with s_block("type_id"):
            # this one should remain constant
            s_byte(0x01, fuzzable=False, name="encoding_mask")
            s_byte(0x00, fuzzable=False, name="namespace_index")
            s_static(pack("<H", 533), name="identifier_numeric")
        with s_block("browse_next_request"):
            request_header_common_block(to_fuzz=False)
            s_group(values=BOOLEAN, name="ReleaseContinuationPoints")
            s_group(values=RANGE_AMOUNT_OF_ELEMENTS,
                    name="array_size")
            with s_block("continuation_points", dep="array_size", dep_value=pack("I", 0), dep_compare="!="):
                opcua_bytes("continuation_point")
            s_opcua_repeat(
                "continuation_points", bound_block_repetitions="array_size", name="continuation_points_repeater")


def build_add_nodes_request_packet(name):
    s_initialize(name)
    header_common_block()
    with s_block("opcua_service"):
        with s_block("type_id"):
            # this one should remain constant
            s_byte(0x01, fuzzable=False, name="encoding_mask")
            s_byte(0x00, fuzzable=False, name="namespace_index")
            s_static(pack("<H", 488), name="identifier_numeric")
        with s_block("add_nodes_request"):
            request_header_common_block(to_fuzz=False)
            with s_block("nodes_to_add"):
                s_group(values=RANGE_AMOUNT_OF_ELEMENTS,
                        name="array_size")
                with s_block("add_nodes_item", dep="array_size", dep_value=pack("I", 0), dep_compare="!="):
                    node_id_common_block("ParentNodeId", 2)
                    node_id_common_block("ReferenceTypeId", 3)
                    node_id_common_block("RequestedNewNodeId", 4)
                    qualified_name_common_block("BrowseName")
                    s_group(values=NODE_CLASS, name="NodeClass")
                    extension_object_common_block("NodeAttributes")
                    node_id_common_block("TypeDefinition", 5)
                s_opcua_repeat(
                    "add_nodes_item", bound_block_repetitions="array_size", name="add_nodes_item_repeater")


def build_history_read_request_packet(name):
    s_initialize(name)
    header_common_block()
    with s_block("opcua_service"):
        with s_block("type_id"):
            # this one should remain constant
            s_byte(0x01, fuzzable=False, name="encoding_mask")
            s_byte(0x00, fuzzable=False, name="namespace_index")
            s_static(pack("<H", 664), name="identifier_numeric")
        with s_block("history_read_request"):
            request_header_common_block(to_fuzz=False)
            extension_object_common_block("HistoryReadDetails")
            s_group(values=TIMESTAMP_TO_RETURN, name="TimestampsToReturn")
            s_group(values=BOOLEAN, name="ReleaseContinuationPoints")
            with s_block("NodesToRead"):
                s_group(values=RANGE_AMOUNT_OF_ELEMENTS,
                        name="array_size")
                with s_block("HistoryReadValueId", dep="array_size", dep_value=pack("I", 0), dep_compare="!="):
                    node_id_common_block("node_id")
                    opcua_string("index_range")
                    qualified_name_common_block("data_encoding")
                    opcua_bytes("Contpoit")
                s_opcua_repeat(
                    "HistoryReadValueId", bound_block_repetitions="array_size", name="read_value_id_repeater")


def init_request_by_service(name):
    if name not in services_callbacks_dict:
        raise ValueError("service name does not exist")
    # callback call
    services_callbacks_dict[name](name)


services_callbacks_dict = {
    "read_request": build_read_request_packet,
    "browse_request": build_browse_request_packet,
    "create_subscription_request": build_create_subscription_request_packet,
    "browse_next_request": build_browse_next_request_packet,
    "add_nodes_request": build_add_nodes_request_packet,
    "history_read_request": build_history_read_request_packet,
}


def raise_if_request_name_invalid(req):
    if req not in services_callbacks_dict.keys():
        raise Exception("request name invalid")
