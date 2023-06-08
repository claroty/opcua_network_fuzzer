import time
import logging
import string
import random
import os
from boofuzz import *
from opcua_session import create_session, OBJECT
from opcua_services import *
from opcua_utils import *
from fuzzer import Fuzzer, _s_update
import argparse

IS_TEST_RUN = False


class OPCUA_Deep_Fuzzer(Fuzzer):
    def __init__(self, target_app_name, request_name, *args, **kwargs):
        self.session_info = {}
        self.target_app = target_app_name
        self.sanity_payload = None
        self.request_name = request_name

        raise_if_target_app_invalid(target_app_name)
        raise_if_request_name_invalid(request_name)
        if not os.path.exists("./logs"):
            os.makedirs("./logs")
        logging.basicConfig(handlers=[logging.FileHandler(filename=f'./logs/fuzzer_runtime_{time.strftime("%m%d-%H%M%S")}.log',
                                                          encoding='utf-8', mode='w+')], format='%(asctime)s %(message)s', level=logging.INFO)
        super(OPCUA_Deep_Fuzzer, self).__init__(*args, **kwargs)

    def _init_protocol_structure(self):
        if IS_TEST_RUN:
            s_initialize("opcua_request_sanity")
            # we need at least two permutations for fuzzer to work
            s_static(b'\x00', name="sanity_payload")
            s_group(name="test", values=[b'\x00', b'\x00'])
        else:
            init_request_by_service(self.request_name)

    def session_pre_send(self, target, fuzz_data_logger, session, sock):
        self.sock = sock
        try:
            secure_channel_id, auth_id, sequence, secure_token_id = create_session(
                self.sock, self.target_app)

            self.session_info[AttributeType.SECURE_CHANNEL_ID] = int.to_bytes(
                secure_channel_id, 4, "little")
            self.session_info[AttributeType.SECURE_TOCKEN_ID] = int.to_bytes(
                secure_token_id, 4, "little")
            self.session_info[AttributeType.SEQUENCE_ID] = int.to_bytes(
                sequence + 3, 4, "little")
            self.session_info[AttributeType.AUTH_ID] = OBJECT.build(auth_id)

            # update the fuzzer
            _s_update("secure_channel_id",
                      self.session_info[AttributeType.SECURE_CHANNEL_ID])
            _s_update("security_token_id",
                      self.session_info[AttributeType.SECURE_TOCKEN_ID])
            _s_update("auth_id", self.session_info[AttributeType.AUTH_ID])
            _s_update("security_sequence_id",
                      self.session_info[AttributeType.SEQUENCE_ID])
            # node id should be prepared beforehand to cope with fuzzable dependency limitation
            _s_update("previously_generated_node_id_1",
                      self.generate_node_id())
            _s_update("previously_generated_node_id_2",
                      self.generate_node_id())
            _s_update("previously_generated_node_id_3",
                      self.generate_node_id())
            _s_update("previously_generated_node_id_4",
                      self.generate_node_id())
            _s_update("previously_generated_node_id_5",
                      self.generate_node_id())

            # Needed for test
            if IS_TEST_RUN:
                self.prepare_sanity_payload()
                _s_update("sanity_payload", self.sanity_payload)
        except Exception as e:
            logging.error(f"session_pre_send {e}")

    def post_actions(self, target, fuzz_data_logger, session, sock):
        try:
            if not IS_TEST_RUN:
                super().post_actions(target, fuzz_data_logger, session, sock)

            close_session(self.sock, self.target_app, self.session_info)
        except Exception as e:
            logging.error(f"post_actions {e}")

    def prepare_sanity_payload(self):
        payload_prepare_sanity = bytearray(get_sanity_payload(self.target_app))

        secure_channel_id = self.session_info[AttributeType.SECURE_CHANNEL_ID]
        secure_sequence_id = self.session_info[AttributeType.SEQUENCE_ID]
        auth_id = self.session_info[AttributeType.AUTH_ID]

        set_data_at_offset(payload_prepare_sanity,
                           secure_channel_id, AttributeType.SECURE_CHANNEL_ID)
        set_data_at_offset(payload_prepare_sanity,
                           secure_sequence_id, AttributeType.SEQUENCE_ID)
        set_data_at_offset(payload_prepare_sanity,
                           auth_id, AttributeType.AUTH_ID)

        # increase size by one to be able to send single packet on fuzzing
        size_offset = offsets_dict[AttributeType.SIZE]
        msg_size = int.from_bytes(
            payload_prepare_sanity[size_offset: size_offset + 4], "little")
        set_data_at_offset(payload_prepare_sanity,  int.to_bytes(
            msg_size + 1, 4, "little"), AttributeType.SIZE)
        self.sanity_payload = bytes(payload_prepare_sanity)

    def fuzz(self):
        try:
            request_name = "opcua_request_sanity" if IS_TEST_RUN else self.request_name
            self.session.connect(s_get(request_name))
            self.session.fuzz()

        except Exception as e:
            logging.error("This error happenned during fuzz function")
            logging.error(e)
            print("ERROR Occured!")

    @staticmethod
    def generate_node_id():
        node_id = bytearray()
        node_id_type = random.randrange(6)
        node_id += pack("<B", node_id_type)
        if node_id_type == 0:
            identifier = random.randbytes(1)
            node_id += identifier
        elif node_id_type == 1:
            namespace_index = random.randbytes(1)
            identifier = random.randbytes(2)
            node_id += namespace_index
            node_id += identifier
        elif node_id_type == 2:
            namespace_index = random.randbytes(2)
            identifier = random.randbytes(4)
            node_id += namespace_index
            node_id += identifier
        elif node_id_type == 3:
            namespace_index = random.randbytes(2)
            node_id += namespace_index
            possible_ranges = [i for i in range(25)]
            possible_ranges.append(-1)
            str_size = random.choice(possible_ranges)
            node_id += pack("<i", str_size)
            if str_size != -1:
                str = ''.join(random.choices(
                    string.ascii_uppercase + string.digits, k=str_size))
                node_id += bytearray(str.encode('utf-8'))
        elif node_id_type == 4:
            namespace_index = random.randbytes(2)
            node_id += namespace_index
            guid = random.randbytes(16)
            node_id += guid
        elif node_id_type == 5:
            namespace_index = random.randbytes(2)
            node_id += namespace_index
            possible_ranges = [i for i in range(25)]
            possible_ranges.append(-1)
            bytes_size = random.choice(possible_ranges)
            node_id += pack("<i", bytes_size)
            if bytes_size != -1:
                opcua_bytes = random.randbytes(bytes_size)
                node_id += opcua_bytes

        if node_id is None or node_id == b"":
            raise AttributeError("node id is null!")

        return bytes(node_id)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-ti", "--target_host_ip",
                        required=True, help="Target server IP")
    parser.add_argument("-tp", "--target_host_port",
                        required=True, type=int, help="Target server port")
    parser.add_argument("-ta", "--target_app_name", required=True,
                        choices=target_apps, help=f"OPCUA server type")
    parser.add_argument("-r", "--request_opcua_to_fuzz", required=True, choices=list(services_callbacks_dict.keys()),
                        help=f"The type of the opcua request to fuzz")

    args = parser.parse_args()

    enip_fuzzer = OPCUA_Deep_Fuzzer(target_app_name=args.target_app_name,
                                    request_name=args.request_opcua_to_fuzz,
                                    target_ip=args.target_host_ip,
                                    target_port=args.target_host_port)
    enip_fuzzer.init()
    enip_fuzzer.fuzz()


if __name__ == "__main__":
    main()
