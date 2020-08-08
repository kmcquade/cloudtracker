from colors import color


def make_list(obj):
    """Convert an object to a list if it is not already"""
    if isinstance(obj, list):
        return obj
    return [obj]


def colored_print(text, use_color=True, color_name='white'):
    """Print with or without color codes"""
    if use_color:
        print(color(text, fg=color_name))
    else:
        print(text)
