from faraday.server.debouncer import debounce_workspace_update
from faraday.server.app import get_debouncer

debouncer = get_debouncer()


def test_debouncer_queue():

    def _function_to_debounce(param1, param2):
        print(f"executing debounced function with params {param1} and {param2}")

    for param1, param2 in zip([1,1,1,1,1,2,2,2,2,2], [2,2,2,2,2,1,1,1,1,1]):
        print(f"param1: {param1}, param2: {param2}")
        debouncer.debounce(_function_to_debounce, {'param1':param1, 'param2':param2})

    assert len(debouncer.actions) == 2


def test_update_workspace_update_date():
    debouncer.actions = set()
    for i in range(100):
        debounce_workspace_update('workspace-test',debouncer)
        debounce_workspace_update('Adriano',debouncer)

    assert len(debouncer.actions) == 1

