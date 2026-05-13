# ============================================
# engine/usb_monitor.py
# ============================================

import psutil


def detect_usb():

    partitions = psutil.disk_partitions()

    for partition in partitions:

        try:

            if 'removable' in partition.opts:

                print(
                    f"[USB] "
                    f"{partition.device}"
                )

        except:
            pass