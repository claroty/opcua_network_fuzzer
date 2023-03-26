# this file is used for pwn2own competition against 5 opc targets
from enum import Enum
from boofuzz import *
from raw_messages_opcua import get_raw_close_session_messages
from struct import pack, unpack

OPCUA_RESP_SIZE = 1024

target_apps = ["softing", "dotnetstd",
               "prosys", "unified", "kepware", "triangle", "ignition"]

opcua_services_list = [8917, 631, 11889, 11890, 263, 266, 269, 272, 275, 278, 281, 284, 287, 298, 8251,
                       310, 391, 394, 397, 422, 425, 306, 314, 428, 431, 434, 437, 440, 443,
                       446, 449, 452, 455, 346, 458, 461, 464, 318, 321, 324, 327, 940, 467, 470,
                       473, 476, 479, 482, 351, 354, 357, 360, 363, 366, 369, 372, 375, 378, 485,
                       488, 491, 381, 494, 497, 384, 500, 503, 387, 506, 509, 513, 516, 520, 524,
                       527, 530, 533, 536, 539, 542, 545, 548, 551, 554, 557, 560, 563, 566, 569,
                       333, 337, 343, 572, 575, 579, 582, 585, 588, 591, 594, 597, 600, 603, 606,
                       609, 612, 615, 618, 621, 624, 628, 260, 634, 637, 640, 643, 646, 649, 652,
                       655, 658, 11226, 11227, 661, 664, 667, 670, 673, 676, 679, 682, 11300, 685, 688,
                       691, 694, 697, 931, 700, 703, 706, 709, 712, 715, 721, 724, 727, 950, 730,
                       733, 736, 739, 742, 745, 748, 751, 754, 757, 760, 763, 766, 769, 772, 775,
                       778, 781, 784, 787, 790, 793, 796, 799, 802, 805, 947, 811, 808, 916, 919,
                       922, 820, 823, 826, 829, 832, 835, 838, 841, 844, 847, 850, 401, 404, 407,
                       410, 413, 416, 419, 340, 855, 11957, 11958, 858, 861, 864, 867, 870, 873, 301,
                       876, 879, 899, 886, 889, 12181, 12182, 12089, 12090, 896, 893]

OPCUA_SERVICE = [i.to_bytes(2, "little") for i in opcua_services_list]


opcua_services_list_unified = [631, 11226, 11227, 11300, 11957, 11958, 12089, 12090, 12181, 12182, 260, 263, 266, 269, 272, 275, 278, 281, 284, 287, 298, 301, 306, 310, 314, 318, 321, 324, 327, 333, 340, 346, 351, 354, 357, 360, 363, 366, 369, 372, 375, 378, 381, 384, 387, 391, 394, 397, 401, 404, 407, 413, 416, 419, 422, 425, 428, 431, 434, 437, 440, 443, 449, 455, 458, 461, 464, 467, 470, 473, 476, 479, 482, 485, 488, 491, 494, 497, 500, 503, 506, 509, 513, 516, 520, 524, 527, 530, 533, 536, 539, 542, 545, 548, 551, 554, 557, 560, 563, 566,
                               569, 572, 575, 579, 582, 585, 588, 594, 597, 600, 603, 606, 609, 612, 615, 618, 621, 624, 628, 634, 637, 640, 646, 649, 652, 655, 658, 661, 664, 667, 670, 673, 676, 679, 682, 685, 688, 691, 694, 697, 700, 703, 706, 709, 712, 715, 724, 727, 730, 736, 739, 742, 745, 748, 751, 754, 757, 760, 763, 766, 769, 772, 775, 778, 781, 784, 787, 790, 793, 796, 799, 802, 805, 808, 811, 820, 823, 8251, 826, 829, 832, 835, 838, 841, 844, 847, 850, 855, 858, 861, 864, 867, 870, 873, 876, 879, 886, 889, 8917, 893, 896, 899, 916, 919, 922, 940, 950, ]
opcua_services_list_dotnetstd = [631, 11889, 11890, 263, 266, 269, 272, 275, 278, 281, 284, 287, 298, 8251, 8917, 310, 391, 394, 397, 422, 425, 306, 314, 428, 431, 434, 437, 440, 443, 449, 455, 346, 458, 461, 464, 318, 321, 324, 327, 940, 467, 470, 473, 476, 479, 482, 351, 354, 357, 360, 363, 366, 369, 372, 375, 378, 485, 491, 381, 497, 384, 503, 387, 509, 513, 516, 520, 524, 527, 530, 533, 536, 539, 542, 545, 548, 551, 554, 557, 560, 563, 566, 569, 333, 337, 343, 572, 575, 579, 582, 585, 588, 591, 594, 597, 600, 603, 606, 609, 612, 615, 618, 624, 628,
                                 260, 634, 637, 640, 643, 646, 649, 652, 655, 658, 11226, 11227, 661, 664, 667, 670, 673, 676, 679, 682, 11300, 685, 688, 691, 694, 697, 931, 700, 703, 706, 709, 712, 715, 721, 724, 727, 950, 730, 733, 736, 739, 742, 745, 748, 751, 754, 757, 760, 763, 766, 769, 772, 775, 778, 781, 784, 787, 790, 793, 796, 799, 802, 805, 947, 811, 808, 916, 919, 922, 820, 823, 826, 829, 832, 835, 838, 844, 847, 850, 401, 404, 407, 410, 413, 416, 419, 340, 855, 11957, 11958, 858, 861, 864, 867, 870, 873, 301, 876, 879, 899, 886, 889, 12181, 12182, 12089, 12090, 896, 893]
opcua_services_list_triangle = [631, 11889, 11890, 263, 266, 269, 272, 275, 278, 281, 284, 287, 298, 8251, 310, 394, 397, 422, 425, 306, 314, 428, 431, 434, 437, 440, 449, 455, 346, 458, 461, 464, 318, 321, 324, 327, 940, 467, 470, 473, 476, 479, 482, 357, 366, 369, 378, 488, 491, 381, 494, 497, 500, 503, 387, 506, 509, 520, 524, 527, 530, 533, 536, 539, 542, 545, 551, 554, 557, 560, 563, 566, 569, 337, 343, 572, 575, 579, 582, 585, 588, 591, 600, 603, 606, 609, 612, 615,
                                618, 621, 624, 628, 260, 634, 637, 640, 643, 646, 652, 655, 658, 11226, 11227, 661, 664, 667, 670, 673, 676, 682, 11300, 685, 691, 694, 697, 931, 700, 703, 706, 709, 712, 715, 721, 724, 727, 733, 736, 742, 745, 748, 751, 754, 757, 760, 763, 766, 769, 772, 775, 778, 781, 784, 787, 790, 793, 796, 799, 802, 805, 947, 811, 916, 919, 922, 826, 829, 832, 835, 838, 841, 844, 847, 850, 401, 404, 407, 410, 413, 416, 419, 340, 855, 11957, 11958, 864, 867, 870, 889, 12089, 896, 893]
opcua_services_list_prosys = [631, 11889, 11890, 263, 266, 269, 272, 275, 278, 281, 284, 287, 298, 8251, 310, 394, 397, 425, 306, 314, 431, 434, 440, 446, 449, 452, 455, 346, 458, 461, 464, 318, 321, 324, 327, 940, 470, 473, 476, 479, 482, 357, 366, 369, 378, 488, 491, 381, 494, 497, 500, 387, 506, 509, 516, 520, 524, 527, 530, 533, 539, 545, 554, 557, 560, 563, 566, 569, 337, 343,
                              575, 579, 582, 600, 603, 615, 618, 621, 624, 628, 260, 637, 640, 646, 652, 11226, 664, 670, 673, 676, 682, 11300, 685, 691, 694, 931, 700, 706, 712, 730, 742, 745, 748, 751, 754, 757, 760, 763, 766, 769, 775, 778, 781, 784, 787, 790, 793, 796, 799, 802, 919, 826, 832, 841, 844, 847, 401, 404, 407, 410, 413, 416, 419, 340, 855, 11958, 864, 867, 870, 879, 899, 889, 12089, 896, 893, ]
opcua_services_list_kepware = [631, 422, 428, 437, 446, 452, 461, 467, 473, 479, 527,
                               533, 554, 560, 566, 673, 751, 763, 769, 775, 781, 787, 793, 799, 826, 832, 841, 847, ]
opcua_services_list_softing = [631, 11889, 11890, 263, 266, 269, 272, 275, 278, 281, 284, 287, 298, 8251, 310, 394, 397, 422, 425, 306, 314, 428, 431, 434, 437, 440, 449, 455, 346, 458, 461, 464, 318, 321, 324, 327, 940, 467, 470, 473, 476, 479, 482, 357, 366, 369, 378, 488, 491, 381, 494, 497, 500, 503, 506, 509, 520, 524, 527, 530, 533, 536, 539, 542, 545, 551, 554, 557, 560, 563, 566, 569, 337, 343, 572, 575, 579, 582, 585, 588, 591, 600, 603, 606, 609, 612, 615, 618,
                               621, 624, 628, 260, 634, 637, 640, 643, 646, 652, 655, 658, 11226, 11227, 661, 664, 667, 670, 673, 676, 682, 11300, 685, 691, 694, 697, 931, 700, 703, 706, 709, 712, 715, 721, 724, 727, 733, 736, 742, 745, 748, 751, 754, 757, 760, 763, 766, 769, 772, 775, 778, 781, 784, 787, 790, 793, 796, 799, 802, 805, 947, 811, 916, 919, 922, 826, 829, 832, 835, 838, 841, 844, 847, 850, 401, 404, 407, 410, 413, 416, 419, 340, 855, 11957, 11958, 864, 867, 870, 876, 889, 12089, 896, 893, ]


class AttributeType(Enum):
    SECURE_CHANNEL_ID = 1
    SEQUENCE_ID = 2
    REQUEST_ID = 3
    AUTH_ID = 4
    SIZE = 5
    SERVICE_ID = 6
    SERVICE_RESULT = 8
    ERROR_RESULT = 9
    MSG_TYPE = 10
    SECURE_TOCKEN_ID = 11


# Note that those offset are correct only for specific request types, such are close types
offsets_dict = {AttributeType.MSG_TYPE: 0, AttributeType.SIZE: 4, AttributeType.SECURE_CHANNEL_ID: 8,
                AttributeType.SECURE_TOCKEN_ID: 12,
                AttributeType.ERROR_RESULT: 8, AttributeType.SEQUENCE_ID: 16, AttributeType.REQUEST_ID: 20,
                AttributeType.SERVICE_ID: 26, AttributeType.AUTH_ID: 28, AttributeType.SERVICE_RESULT: 40}


class ResponseType(Enum):
    SERVICE_FAULT = 1
    ERROR = 2
    REGULAR_RESPONSE = 3


class OPCUARepeat(Repeat):
    def __init__(
        self,
        name=None,
        block_name=None,
        request=None,
        bound_block_repetitions=None,
        *args,
        **kwargs
    ):
        self.bound_block_repetitions = bound_block_repetitions
        super(OPCUARepeat, self).__init__(
            name, block_name, request, fuzzable=bound_block_repetitions is None, *args, **kwargs)

    def get_value(self, mutation_context=None):
        if self.bound_block_repetitions is not None:
            qualified_name_list = [n for n in self.request.names if n.rsplit(
                ".")[-1] == self.bound_block_repetitions]
            if len(qualified_name_list) != 1:
                raise Exception(
                    "block for repetitions does not exist or there are more than 1!")
            qualified_name = qualified_name_list[0]
            if mutation_context is None or qualified_name not in mutation_context.mutations:
                value = self.request.names[qualified_name].original_value()
            else:
                value = mutation_context.mutations[qualified_name].value
            # the "non repeated" block is already rendered
            return 0 if value == b'\x00' else unpack("<I", value)[0] - 1
        else:
            return super().get_value()


def s_opcua_repeat(block_name=None, bound_block_repetitions=None, name=None):
    blocks.CURRENT.push(
        OPCUARepeat(
            name=name,
            block_name=block_name,
            request=blocks.CURRENT,
            bound_block_repetitions=bound_block_repetitions
        )
    )


def raise_if_target_app_invalid(argument):
    if argument not in target_apps:
        raise ValueError("name of the target incorrect")

# getters:


def get_services_list(target_app):
    if target_app == "softing":
        service_list = opcua_services_list_softing
    elif target_app == "dotnetstd":
        service_list = opcua_services_list_dotnetstd
    elif target_app == "prosys":
        service_list = opcua_services_list_prosys
    elif target_app == "unified":
        service_list = opcua_services_list_unified
    elif target_app == "kepware":
        service_list = opcua_services_list_kepware
    elif target_app == "triangle":
        service_list = opcua_services_list_triangle
    # lazy for ignition
    elif target_app == 'ignition':
        service_list = opcua_services_list_dotnetstd

    else:
        raise Exception("Invalid target app name")

    return [i.to_bytes(2, "little") for i in service_list]


def get_sanity_payload(target_app):
    if target_app == "softing":
        return SOFTING_MSG_READ
    if target_app == "dotnetstd":
        return DOTNET_MSG_READ
    if target_app == "prosys":
        return PROSYS_MSG_READ
    if target_app == "unified":
        return UA_ANSI_C_MSG_READ
    if target_app == "kepware":
        return KEPWARE_MSG_READ
    if target_app == "triangle":
        return TRIANGLE_MSG_READ
    if target_app == "ignition":
        return IGNITION_MSG_READ


def receive_rest_of_response(sock, response, report_service_fault):
    tmp_resp = bytearray(response)
    is_service_fault = check_service_fault(response)
    if report_service_fault and is_service_fault:
        raise ValueError("Got ServiceFault")

    payload_size_left = get_size_of_the_payload(response) - len(response)
    while payload_size_left > 0:
        response = sock.recv(OPCUA_RESP_SIZE)
        tmp_resp += response
        payload_size_left -= len(response)
    return tmp_resp


def close_session(sock, target_app, ses_info):
    try:
        close_session_payload, close_channel_payload = get_raw_close_session_messages(
            target_app)
        if target_app in ["prosys", "kepware", "softing", "unified", "triangle", "ignition"]:
            # close session
            close_session_payload = bytearray(close_session_payload)

            set_data_at_offset(
                close_session_payload, ses_info[AttributeType.SECURE_CHANNEL_ID], AttributeType.SECURE_CHANNEL_ID)

            set_data_at_offset(
                close_session_payload, ses_info[AttributeType.SECURE_TOCKEN_ID], AttributeType.SECURE_TOCKEN_ID)

            sequence_id = int.to_bytes(int.from_bytes(
                ses_info[AttributeType.SEQUENCE_ID], "little") + 1, 4, "little")
            set_data_at_offset(close_session_payload,
                               sequence_id, AttributeType.SEQUENCE_ID)

            request_id = int.to_bytes(5, 4, "little")
            set_data_at_offset(close_session_payload,
                               request_id, AttributeType.REQUEST_ID)

            set_data_at_offset(
                close_session_payload, ses_info[AttributeType.AUTH_ID], AttributeType.AUTH_ID)

            sock.send(close_session_payload)
            sock.recv(OPCUA_RESP_SIZE)
            # self.receive_rest_of_response(response)

            # close channel
            close_channel_payload = bytearray(close_channel_payload)

            set_data_at_offset(
                close_channel_payload, ses_info[AttributeType.SECURE_CHANNEL_ID], AttributeType.SECURE_CHANNEL_ID)
            set_data_at_offset(
                close_channel_payload, ses_info[AttributeType.SECURE_TOCKEN_ID], AttributeType.SECURE_TOCKEN_ID)
            sequence_id = int.to_bytes(int.from_bytes(
                ses_info[AttributeType.SEQUENCE_ID], "little") + 2, 4, "little")
            set_data_at_offset(close_channel_payload,
                               sequence_id, AttributeType.SEQUENCE_ID)

            request_id = int.to_bytes(6, 4, "little")
            set_data_at_offset(close_channel_payload,
                               request_id, AttributeType.REQUEST_ID)

            sock.send(close_channel_payload)

    except Exception as e:
        # some exceptions may occur during the close session, we do not want to count them as failure
        # in contrast to boofuzz
        pass


def set_data_at_offset(payload, value, atype):
    offset = offsets_dict[atype]
    attribute_size = len(value)
    payload[offset: offset + attribute_size] = value


def get_size_of_the_payload(payload):
    offset = offsets_dict[AttributeType.SIZE]
    return int.from_bytes(payload[offset: offset + 4], "little")


def check_service_fault_or_error(payload):
    service_fault = check_service_fault(payload)
    if service_fault is not None:
        return ResponseType.SERVICE_FAULT, service_fault

    error = check_error_on_response(payload)
    if error is not None:
        return ResponseType.ERROR, error

    service_number = get_service_id_as_int(payload)
    return ResponseType.REGULAR_RESPONSE, service_number


def get_service_id_as_int(payload):
    offset = offsets_dict[AttributeType.SERVICE_ID]
    return unpack("<H", payload[offset: offset + 2])[0]


def check_service_fault(payload):
    offset = offsets_dict[AttributeType.SERVICE_ID]
    if int.from_bytes(payload[offset: offset + 2], "little") == 397:
        offset = offsets_dict[AttributeType.SERVICE_RESULT]
        return unpack("<I", payload[offset: offset + 4])[0]


def check_error_on_response(payload):
    offset = offsets_dict[AttributeType.MSG_TYPE]
    if payload[offset: offset + 3] == b'ERR':
        offset = offsets_dict[AttributeType.ERROR_RESULT]
        return unpack("<I", payload[offset: offset + 4])[0]

##########################################
#
# SOFTING ANSI C
#
##########################################


SOFTING_MSG_READ = b'\x4d\x53\x47\x46\x92\x00\x00\x00\x02\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\
\x04\x00\x00\x00\x01\x00\x77\x02\x05\x00\x00\x20\x00\x00\x00\x2c\x44\x19\x0c\x19\
\xf4\x32\x13\xc3\xfa\x00\xd4\xdf\x03\x90\xca\xd7\x3d\x73\xd1\x73\x27\xf3\xa7\x1d\
\xc7\x86\x2f\xd0\xf9\xcb\xc2\x86\xca\x5a\xa5\xa4\xd0\xd7\x01\x03\x00\x00\x00\x00\
\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00\x01\x00\xcf\x08\x0d\x00\x00\x00\xff\xff\
\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xce\x08\x0d\x00\x00\x00\xff\xff\xff\xff\
\x00\x00\xff\xff\xff\xff'


##########################################
#
# .NET Standard
#
##########################################

# Close not implemented
DOTNET_MSG_READ = b"\x4d\x53\x47\x46\xd6\x01\x00\x00\x22\x00\x00\x00\x01\x00\x00\x00\x36\x00\x00\x00\
\x04\x00\x00\x00\x01\x00\x77\x02\x05\x00\x00\x20\x00\x00\x00\x0c\x4f\xd0\xa4\xa7\
\x2b\x85\xf0\x94\x30\x46\x45\xf1\x79\xe3\xc3\x67\xd6\x4e\xee\x82\x58\xaf\xd6\xe6\
\x16\x3d\x04\x38\x8b\x5f\x07\x9d\xd4\xfe\xd9\x9b\xd1\xd7\x01\x43\x42\x0f\x00\x00\
\x00\x00\x00\xff\xff\xff\xff\x88\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x03\x00\x00\x00\x14\x00\x00\x00\x01\x00\xcf\x08\x0d\x00\x00\x00\xff\xff\
\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xb6\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\
\x00\x00\xff\xff\xff\xff\x01\x00\xaf\x0a\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\
\xff\xff\xff\xff\x01\x00\x6f\x32\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\
\xff\xff\x01\x00\xb1\x0a\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\
\x01\x00\xb0\x0a\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\
\xb7\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xe0\x08\
\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xc2\x2d\x0d\x00\
\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xbe\x2d\x0d\x00\x00\x00\
\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x85\x2f\x0d\x00\x00\x00\xff\xff\
\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x86\x2f\x0d\x00\x00\x00\xff\xff\xff\xff\
\x00\x00\xff\xff\xff\xff\x01\x00\x87\x2f\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\
\xff\xff\xff\xff\x01\x00\x88\x2f\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\
\xff\xff\x01\x00\xbd\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\
\x01\x00\xc1\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\
\xb9\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xbf\x2d\
\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xc0\x2d\x0d\x00\
\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xbb\x2d\x0d\x00\x00\x00\
\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff"

##########################################
#
# Unified Automation - ANSI C
#
##########################################


UA_ANSI_C_MSG_READ = b"\x4d\x53\x47\x46\xb6\x01\x00\x00\xc7\x26\xe1\x25\x01\x00\x00\x00\x36\x00\x00\x00\
\x04\x00\x00\x00\x01\x00\x77\x02\x02\x00\x00\x8d\x13\xce\x25\xe6\x61\xb6\x13\x61\
\xd9\xd7\x01\x43\x42\x0f\x00\x00\x00\x00\x00\xff\xff\xff\xff\x88\x13\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x14\x00\x00\x00\x01\x00\
\xcf\x08\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xb6\x2d\
\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xaf\x0a\x0d\x00\
\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x6f\x32\x0d\x00\x00\x00\
\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xb1\x0a\x0d\x00\x00\x00\xff\xff\
\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xb0\x0a\x0d\x00\x00\x00\xff\xff\xff\xff\
\x00\x00\xff\xff\xff\xff\x01\x00\xb7\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\
\xff\xff\xff\xff\x01\x00\xe0\x08\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\
\xff\xff\x01\x00\xc2\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\
\x01\x00\xbe\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\
\x85\x2f\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x86\x2f\
\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x87\x2f\x0d\x00\
\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x88\x2f\x0d\x00\x00\x00\
\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xbd\x2d\x0d\x00\x00\x00\xff\xff\
\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xc1\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\
\x00\x00\xff\xff\xff\xff\x01\x00\xb9\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\
\xff\xff\xff\xff\x01\x00\xbf\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\
\xff\xff\x01\x00\xc0\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\
\x01\x00\xbb\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff"


##########################################
#
# Prosys - JAVA
#
##########################################


PROSYS_MSG_READ = b"\x4d\x53\x47\x46\xd6\x01\x00\x00\x65\x04\x00\x00\x01\x00\x00\x00\x36\x00\x00\x00\
\x04\x00\x00\x00\x01\x00\x77\x02\x05\x00\x00\x20\x00\x00\x00\x03\x3b\x74\x2d\x3b\
\xa1\x99\xc8\x67\x21\x4f\x8a\xfe\x87\x2a\x0f\xa0\x5f\xc3\x73\xa0\xa6\xd6\x15\x69\
\x29\xf1\x76\x27\x3d\xbc\x83\xd6\x65\x26\x8d\xa4\xd4\xd7\x01\x43\x42\x0f\x00\x00\
\x00\x00\x00\xff\xff\xff\xff\x88\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x03\x00\x00\x00\x14\x00\x00\x00\x01\x00\xcf\x08\x0d\x00\x00\x00\xff\xff\
\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xb6\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\
\x00\x00\xff\xff\xff\xff\x01\x00\xaf\x0a\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\
\xff\xff\xff\xff\x01\x00\x6f\x32\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\
\xff\xff\x01\x00\xb1\x0a\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\
\x01\x00\xb0\x0a\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\
\xb7\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xe0\x08\
\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xc2\x2d\x0d\x00\
\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xbe\x2d\x0d\x00\x00\x00\
\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x85\x2f\x0d\x00\x00\x00\xff\xff\
\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x86\x2f\x0d\x00\x00\x00\xff\xff\xff\xff\
\x00\x00\xff\xff\xff\xff\x01\x00\x87\x2f\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\
\xff\xff\xff\xff\x01\x00\x88\x2f\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\
\xff\xff\x01\x00\xbd\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\
\x01\x00\xc1\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\
\xb9\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xbf\x2d\
\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xc0\x2d\x0d\x00\
\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xbb\x2d\x0d\x00\x00\x00\
\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff"


##########################################
#
# KEPware
#
##########################################


KEPWARE_MSG_READ = b"\x4d\x53\x47\x46\xb6\x01\x00\x00\x09\x94\x85\x3e\x01\x00\x00\x00\x36\x00\x00\x00\
\x04\x00\x00\x00\x01\x00\x77\x02\x02\x00\x00\x64\xf3\xa8\x25\x73\x71\xd3\x3e\x51\
\xd5\xd7\x01\x43\x42\x0f\x00\x00\x00\x00\x00\xff\xff\xff\xff\x88\x13\x00\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x14\x00\x00\x00\x01\x00\
\xcf\x08\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xb6\x2d\
\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xaf\x0a\x0d\x00\
\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x6f\x32\x0d\x00\x00\x00\
\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xb1\x0a\x0d\x00\x00\x00\xff\xff\
\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xb0\x0a\x0d\x00\x00\x00\xff\xff\xff\xff\
\x00\x00\xff\xff\xff\xff\x01\x00\xb7\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\
\xff\xff\xff\xff\x01\x00\xe0\x08\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\
\xff\xff\x01\x00\xc2\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\
\x01\x00\xbe\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\
\x85\x2f\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x86\x2f\
\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x87\x2f\x0d\x00\
\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x88\x2f\x0d\x00\x00\x00\
\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xbd\x2d\x0d\x00\x00\x00\xff\xff\
\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xc1\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\
\x00\x00\xff\xff\xff\xff\x01\x00\xb9\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\
\xff\xff\xff\xff\x01\x00\xbf\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\
\xff\xff\x01\x00\xc0\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\
\x01\x00\xbb\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff"


##########################################
#
# Triangle
#
##########################################


TRIANGLE_MSG_READ = b"\x4d\x53\x47\x46\xd6\x01\x00\x00\x04\x00\x00\x00\x01\x00\x00\x00\x36\x00\x00\x00\
\x04\x00\x00\x00\x01\x00\x77\x02\x05\x00\x00\x20\x00\x00\x00\x12\x68\x27\x67\xff\
\x53\x61\x3e\xd3\x9d\x47\x79\xd7\x3e\x64\xe7\xf9\x2c\x75\x61\x03\xcd\x92\xf0\xbc\
\x14\x52\xe2\x89\xaf\x1c\x83\xb9\x85\x97\xf0\x20\xd7\xd7\x01\x43\x42\x0f\x00\x00\
\x00\x00\x00\xff\xff\xff\xff\x88\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
\x00\x00\x03\x00\x00\x00\x14\x00\x00\x00\x01\x00\xcf\x08\x0d\x00\x00\x00\xff\xff\
\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xb6\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\
\x00\x00\xff\xff\xff\xff\x01\x00\xaf\x0a\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\
\xff\xff\xff\xff\x01\x00\x6f\x32\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\
\xff\xff\x01\x00\xb1\x0a\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\
\x01\x00\xb0\x0a\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\
\xb7\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xe0\x08\
\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xc2\x2d\x0d\x00\
\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xbe\x2d\x0d\x00\x00\x00\
\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x85\x2f\x0d\x00\x00\x00\xff\xff\
\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\x86\x2f\x0d\x00\x00\x00\xff\xff\xff\xff\
\x00\x00\xff\xff\xff\xff\x01\x00\x87\x2f\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\
\xff\xff\xff\xff\x01\x00\x88\x2f\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\
\xff\xff\x01\x00\xbd\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\
\x01\x00\xc1\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\
\xb9\x2d\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xbf\x2d\
\x0d\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xc0\x2d\x0d\x00\
\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xbb\x2d\x0d\x00\x00\x00\
\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff"


##########################################
#
# Ignition
#
##########################################


IGNITION_MSG_READ = b"MSGF\x92\x00\x00\x00\n\x00\x00\x00\x0c\x00\x00\x00\x04\x00\x00\
\x00\x04\x00\x00\x00\x01\x00w\x02\x05\x00\x00 \x00\x00\x00\x89\r\x17\x9f\x8c\xd9\xb0\
\r\x91RR\xebQ\xa2zt\xe1\xdf\xff\xb4\x7fX\x86\xb2\x04\xce\x1e\x93\x1c\xfd\x18\x90\
\x7f\x06a\\M\n\xd9\x01CB\x0f\x00\x00\x00\x00\x00\xff\xff\xff\xff\x88\x13\x00\x00\
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x01\
\x00\xb6-\r\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff\x01\x00\xb9-\r\
\x00\x00\x00\xff\xff\xff\xff\x00\x00\xff\xff\xff\xff"

#################
