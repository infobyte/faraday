from gi.repository import Gtk
from functools import wraps

def scrollable(width=-1, height=-1):
    """A function that takes optinal width and height and returns
    the scrollable decorator.
    """

    def scrollable_decorator(func):
        """Takes a function and returns the scroll_object_wrapper."""

        def scroll_object_wrapper(*args, **kwargs):
            """Takes arguments and obtains the original object from
            func(*args, **kwargs). Creates a box and puts the original
            inside that box. Created a scrolled window and puts the
            box inside it.
            """

            box = Gtk.Box()
            original = func(*args, **kwargs)
            scrolled_box = Gtk.ScrolledWindow(None, None)
            scrolled_box.set_min_content_width(width)
            scrolled_box.set_min_content_height(height)
            scrolled_box.add(original)
            box.pack_start(scrolled_box, True, True, 0)
            return box

        return scroll_object_wrapper

    return scrollable_decorator

