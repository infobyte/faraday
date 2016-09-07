from gi.repository import Gtk
from utils.logs import getLogger
from functools import wraps
from compatibility import CompatibleScrolledWindow as GtkScrolledWindow
from persistence.server.server import ServerRequestException

def safe_io_with_server(response_in_emergency):
    """A function that takes a response_in_emergency. It will return
    a safe_decorator, which will try to execture a funcion and in case
    anything happens, it will return the response in emergency.
    """
    def safe_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                res = func(*args, **kwargs)
            except ServerRequestException as e:
                res = response_in_emergency
                getLogger("Server-GTK IO").warning(e)
            return res
        return wrapper
    return safe_decorator

def scrollable(width=-1, height=-1, overlay_scrolling=False):
    """A function that takes optinal width and height and returns
    the scrollable decorator. -1 is the default GTK option for both
    width and height."""
    def scrollable_decorator(func):
        """Takes a function and returns the scroll_object_wrapper."""
        @wraps(func)
        def scroll_object_wrapper(*args, **kwargs):
            """Takes arguments and obtains the original object from
            func(*args, **kwargs). Creates a box and puts the original
            inside that box. Creates a scrolled window and puts the
            box inside it.
            """

            original = func(*args, **kwargs)
            scrolled_box = GtkScrolledWindow(None, None)
            scrolled_box.set_min_content_width(width)
            scrolled_box.set_min_content_height(height)
            scrolled_box.set_overlay_scrolling(overlay_scrolling)
            scrolled_box.add(original)
            return scrolled_box

        return scroll_object_wrapper

    return scrollable_decorator
