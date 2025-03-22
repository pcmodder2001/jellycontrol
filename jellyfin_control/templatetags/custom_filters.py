from django import template
from datetime import datetime, timezone
import re

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
    if not value:
        return value

    try:
        # Try parsing with datetime.fromisoformat first
        try:
            # Remove trailing Z and replace with +00:00 for UTC
            cleaned_value = value.replace('Z', '+00:00')
            # Handle microseconds if present
            if '.' in cleaned_value:
                base, ms = cleaned_value.split('.')
                if '+' in ms or '-' in ms:
                    tz = ms[ms.find('+'):] if '+' in ms else ms[ms.find('-'):]
                    ms = ms[:ms.find('+') if '+' in ms else ms.find('-')]
                    ms = ms[:6].ljust(6, '0')  # Pad to exactly 6 digits
                    cleaned_value = f"{base}.{ms}{tz}"
                else:
                    ms = ms[:6].ljust(6, '0')  # Pad to exactly 6 digits
                    cleaned_value = f"{base}.{ms}+00:00"
            
            dt = datetime.fromisoformat(cleaned_value)
        except ValueError:
            # Fallback to parsing common ISO format
            dt = datetime.strptime(value, '%Y-%m-%dT%H:%M:%S.%fZ')
            dt = dt.replace(tzinfo=timezone.utc)
        
        # Convert to local timezone
        dt_local = dt.astimezone()
        return dt_local.strftime('%I:%M %p, %B %d, %Y')
    except Exception as e:
        print(f"Date parsing error for {value}: {str(e)}")
        return value

@register.filter
def split_string(value, delimiter=','):
    return value.split(delimiter)

@register.filter
def split_camelcase(value):
    return ' '.join(re.findall(r'[A-Z]?[a-z]+|[A-Z]{2,}(?=[A-Z][a-z]|\d|\W|$)|\d+', value))

@register.filter
def is_boolean(value):
    return isinstance(value, bool)

@register.filter
def time_ago(value):
    """Convert datetime to '2 hours ago' format"""
    if not value:
        return "Never"
    
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        diff = now - dt

        if diff.days > 7:
            return dt.strftime('%B %d, %Y')
        elif diff.days > 0:
            return f"{diff.days}d ago"
        elif diff.seconds >= 3600:
            hours = diff.seconds // 3600
            return f"{hours}h ago"
        elif diff.seconds >= 60:
            minutes = diff.seconds // 60
            return f"{minutes}m ago"
        else:
            return "Just now"
    except:
        return value

@register.filter
def is_recent(value):
    """Check if the timestamp is within the last 24 hours"""
    if not value:
        return False
    
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        diff = now - dt
        return diff.days < 1
    except:
        return False