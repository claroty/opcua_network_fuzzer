from boofuzz import *
import boofuzz.monitors.external_monitor


def _s_update(name, value):
    """
    Update the value of the named primitive in the currently open request.

    :type  name:  str
    :param name:  Name of object whose value we wish to update
    :type  value: Mixed
    :param value: Updated value
    """

    # the blocks.CURRENT.names need to get the whole qualified.name
    found_names = [
        n for n in blocks.CURRENT.names if n.rsplit(".")[-1] == name]
    if len(found_names) == 1:
        blocks.CURRENT.names[found_names[0]]._default_value = value
    if len(found_names) > 0 and 'previously_generated_node_id' in name:
        for i in found_names:
            blocks.CURRENT.names[i]._default_value = value


# https://boofuzz.readthedocs.io/en/latest/user/static-protocol-definition.html
class Fuzzer(object):
    def __init__(self, target_ip, target_port, packet_name="protocol_packet_type"):
        self.target_ip = target_ip
        self.target_port = target_port
        self.session = None
        self.target = None
        self.packet_name = packet_name

    def _init_target_connection(self):
        # Maybe the target connection was initiated before
        target_connection = SocketConnection(self.target_ip, self.target_port)
        self.target = Target(connection=target_connection)

    def _init_session(self):
        # NOTE: pre, post, start, stop (if not None): they must return True to continue fuzzing
        # index_end=1 for only one session
        self.session = Session(pre_send_callbacks=[self.session_pre_send], post_test_case_callbacks=[self.post_actions],
                               restart_threshold=1, ignore_connection_reset=True, fuzz_db_keep_only_n_pass_cases=1000, index_end=None)
        self.target.procmon = boofuzz.monitors.external_monitor.External(
            pre=self.pre_actions, post=self.post_actions, start=self.start_actions, stop=None)
        self.session.add_target(self.target)

    # NOTE: Must be overriden by successors
    def _init_protocol_structure(self):
        raise NotImplementedError

    # Must call from outside
    def init(self):
        # Init
        self._init_target_connection()
        self._init_session()
        self._init_protocol_structure()

    def fuzz(self):
        self.session.connect(s_get(self.packet_name))
        self.session.fuzz()

    # Actions before sending each packet - in the session context
    def session_pre_send(self, target, fuzz_data_logger, session, sock):
        pass

    # Actions before sending each packet - global context
    def pre_actions(self):
        return True

    # Actions after sending each packet (e.g. checking if target is alive)
    def post_actions(self, target, fuzz_data_logger, session, sock):
        return True

    # Actions before starting to fuzz (happens once)
    def start_actions(self):
        return True
