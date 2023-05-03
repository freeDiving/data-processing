import unittest
from collections import deque
from datetime import datetime
from typing import List, Dict

from src.timeline.moment import Moment


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
    def __init__(self, init_datetime: datetime):
        self.state_machine = StateMachine(
            init_state='host: local action',
            state_list=[
                'host: local action',
                'host: data transmission',
                'cloud: processing',
                'resolver: rendering',
                'resolver: done',
            ],
            transitions={
                0: {
                    'host: user touches screen': 0,
                    'host: add points to stroke': 0,
                    'host: send data pkt to cloud': 1,
                },
                1: {
                    'host: receive ack pkt from cloud': 2,
                },
                2: {
                    'resolver: receive data pkt from cloud': 3,
                },
                3: {
                    'resolver: finish rendering': 4,
                },
            }
        )
        self.state_timeline = dict()
        self.set_state_timeline(init_datetime)

    def transit(self, event: str, timestamp: datetime):
        self.set_state_timeline(timestamp)
        self.state_machine.transit(event)
        self.set_state_timeline(timestamp)

    def is_finished(self):
        return self.state_machine.is_finished()

    def is_next_valid_event(self, event: str):
        return self.state_machine.is_next_valid_event(event)

    def set_state_timeline(self, timestamp: datetime):
        state = self.state_machine.get_state()
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
        del res['resolver: done']
        return res


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

        is_handled = False
        event = '{}: {}'.format(moment.source, moment.name)
        for phase in queue:
            if phase.is_next_valid_event(event):
                phase.transit(event, moment.time)
                if phase.is_finished():
                    phases.append(phase.output())
                    queue.popleft()
                is_handled = True
                break
        if not is_handled:
            if moment.name == 'user touches screen' or moment.name == 'add points to stroke':
                phase = Phase(moment.time)
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
