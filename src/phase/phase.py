import unittest
from collections import deque
from datetime import datetime
from typing import List, Dict

from src.timeline.moment import Moment
from src.utils.time import diff_sec

class StateMachine:
    def __init__(
            self,
            init_state: str,
            state_list: List,
            transitions: Dict
    ):
        self.state_list = state_list
        self.index = self.state_list.index(init_state)
        self.transitions = transitions

    def transit(self, event: str):
        if self.is_finished():
            return
        if event not in self.transitions[self.index]:
            raise Exception("Invalid transition")
        else:
            self.index = self.transitions[self.index][event]

    def get_state(self):
        return self.state_list[self.index]

    def is_next_valid_event(self, event: str):
        return event in self.transitions[self.index]

    def is_finished(self):
        return self.index == len(self.state_list) - 1


class Phase:
    def __init__(self, init_datetime: datetime, host_name: str, resolver_name: str):
        init_state = host_name + ': local action'
        transitions = {
            0: {
                host_name + ': user touches screen': 0,
                host_name + ': add points to stroke': 0,
                host_name + ': send data pkt to cloud': 1,
            },
            1: {
                host_name + ': receive ack pkt from cloud': 2,
                # Special case: receiver might receive data packet earlier than the host receives the ACK.
                resolver_name + ': receive data pkt from cloud': 3,
            },
            2: {
                resolver_name + ': receive data pkt from cloud': 3,
            },
            3: {
                resolver_name + ': finish rendering': 4,
            },
        }
        self.host_name = host_name
        self.resolver_name = resolver_name
        state_list = [
            host_name + ': local action',
            host_name + ': data transmission',
            'cloud: processing',
            resolver_name + ': rendering',
            resolver_name + ': done',
        ]

        self.state_machine = StateMachine(
            init_state=init_state,
            state_list=state_list,
            transitions=transitions
        )
        self.state_timeline = dict()
        self.set_state_timeline(init_datetime)

    def transit(self, event: str, timestamp: datetime):
        # Set the timestamp for the current state.
        self.set_state_timeline(timestamp)
        self.state_machine.transit(event)
        # Set the timestamp for the new state.
        self.set_state_timeline(timestamp)

    def is_finished(self):
        return self.state_machine.is_finished()

    def is_next_valid_event(self, event: str):
        return self.state_machine.is_next_valid_event(event)

    def set_state_timeline(self, timestamp: datetime):
        state = self.state_machine.get_state()
        # New state.
        if state not in self.state_timeline:
            self.state_timeline[state] = {
                'start': timestamp,
                'end': None,
                'duration': None,
            }
            return

        self.state_timeline[state]['end'] = timestamp

    def output(self):
        res = {
            **self.state_timeline,
        }

        del res[self.resolver_name + ': done']
        return res

    def get_e2e_start(self):
        return self.get_state_start(self.host_name + ': local action')

    def get_e2e_end(self):
        return self.get_state_end(self.resolver_name + ': rendering')

    def get_state_start(self, state):
        return self.state_timeline[state]['start']

    def get_state_end(self, state):
        return self.state_timeline[state]['end']

    def is_last_state(self, state_str):
        return state_str == self.resolver_name + ": rendering"

def prepare_phases(timeline: List[Moment]):
    phases = []
    queue = deque()
    found_start = False
    user_touch_events_stack = []
    for moment in timeline:
        if not found_start:
            if not user_touch_events_stack and moment.name == 'user touches screen':
                user_touch_events_stack.append(moment)
            if user_touch_events_stack and moment.name == 'add a stroke':
                found_start = True
            continue

        moment_used_for_transition = False
        event = '{}: {}'.format(moment.source, moment.name)
        for phase in queue:
            if phase.is_next_valid_event(event):
                phase.transit(event, moment.time)
                if phase.is_finished():
                    # phases.append(phase.output())
                    phases.append(phase)
                    queue.popleft()
                moment_used_for_transition = True
                break
            # Start of debug (to-do: add a flag to enable/disable debug)
            """"
            else:  # debug
                if ((moment.source == "resolver" and moment.name == 'end data pkt to cloud')
                        or (moment.source == "resolver" and moment.name == 'receive ack pkt from cloud')
                        or (moment.source == "host" and moment.name == 'receive data pkt from cloud')):
                    print("here")
            # End of debug info
            """
        if not moment_used_for_transition:
            # If this moment is the start of 1a, then create a new phase and append it to the queue.
            if moment.name == 'user touches screen' or moment.name == 'add points to stroke':
                if moment.source == "host":
                    host_name = "host"
                    resolver_name = "resolver"
                else:
                    host_name = "resolver"
                    resolver_name = "host"
                phase = Phase(moment.time, host_name, resolver_name)
                queue.append(phase)
    return phases


class MyTestCase(unittest.TestCase):
    def setUp(self):
        self.state_machine = StateMachine(
            init_state='1',
            state_list=['1', '2', '3'],
            transitions={
                0: {'a': 1, 'b': 2},
                1: {'a': 2, 'b': 0},
                2: {'a': 0, 'b': 1},
            }
        )

    def test_state_machine(self):
        self.assertEqual('1', self.state_machine.get_state())  # add assertion here
        self.state_machine.transit('a')
        self.assertEqual('2', self.state_machine.get_state())  # add assertion here
        self.state_machine.transit('a')
        self.assertEqual('3', self.state_machine.get_state())  # add assertion here

    def test_is_next_valid_state(self):
        self.assertEqual('1', self.state_machine.get_state())  # add assertion here
        self.assertTrue(self.state_machine.is_next_valid_event('a'))
        self.assertTrue(self.state_machine.is_next_valid_event('b'))
        self.assertFalse(self.state_machine.is_next_valid_event('c'))


if __name__ == '__main__':
    unittest.main()
