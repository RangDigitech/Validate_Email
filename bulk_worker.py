import sys
import types

# Create a custom signal module that patches the missing Windows functions
original_signal = __import__('signal')

# Create a wrapper module
class PatchedSignal(types.ModuleType):
    def __getattr__(self, name):
        if name == 'SIGALRM':
            return None
        elif name == 'alarm':
            return lambda x: None
        elif name == 'signal':
            def patched_signal_func(signalnum, handler):
                if signalnum is None:
                    return None
                return original_signal.signal(signalnum, handler)
            return patched_signal_func
        else:
            return getattr(original_signal, name)

# Replace the signal module in sys.modules
patched_signal = PatchedSignal('signal')
sys.modules['signal'] = patched_signal

# Now import RQ components
from rq import Queue
from redis import Redis
from rq.worker import SimpleWorker

listen = ['bulk_queue']

redis_conn = Redis(host='localhost', port=6379, db=0)

if __name__ == '__main__':
    # Create queues list
    queues = [Queue(name, connection=redis_conn) for name in listen]

    # Create SimpleWorker for Windows
    worker = SimpleWorker(queues, connection=redis_conn)

    # Start worker loop
    worker.work()