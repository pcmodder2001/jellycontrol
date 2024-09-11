from django import template
from datetime import datetime

register = template.Library()

@register.filter
def length_to_time(value):
    """
    Converts RunTimeTicks to a human-readable time format (hours and minutes).
    """
    if not value:
        return "N/A"
    
    # Assuming RunTimeTicks is in 100-nanosecond intervals
    seconds = value / 1e7
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{int(hours)}h {int(minutes)}m"


@register.filter
def iso_to_local(value):
    if value:
        try:
            dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
            dt_local = dt.astimezone()
            return dt_local.strftime('%H:%M %p, %B %d, %Y')
        except (ValueError, OSError) as e:
            return value  # In case of an error, return the original value
    return value