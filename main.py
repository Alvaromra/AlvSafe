from engine.realtime import (
    start_realtime_protection
)

from engine.process_monitor import (
    monitor_processes
)

from engine.firewall import (
    monitor_connections
)

print()
print("===== ALVSAFE =====")
print()

monitor_processes()

monitor_connections()

start_realtime_protection()