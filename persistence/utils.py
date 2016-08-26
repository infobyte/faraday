class MoreThanOneObjectFoundByID(Exception):
    def __init__(self, object_id, faulty_list):
        self.object_id = object_id
        self.faulty_list = faulty_list

    def __str__(self):
        return ("More than one object has been found with ID {0}."
                "These are all the objects found with that ID: {1}"
                .format(self.object_id, self.faulty_list))

def force_unique(lst):
    """Takes a list and return its only member if the list len is 1,
    None if list is empty or raises an MoreThanOneObjectFoundByID error
    if list has more than one element.
    """
    if len(lst) == 1:
        return lst[0]
    elif len(lst) == 0:
        return None
    else:
        raise MoreThanOneObjectFoundByID(object_id, lst)