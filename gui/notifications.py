# ============================================
# gui/notifications.py
# ============================================

from plyer import notification


def show_notification(
    title,
    message
):

    notification.notify(
        title=title,
        message=message,
        timeout=5
    )