import imp
import os

from config.configuration import getInstanceConfiguration

CONF = getInstanceConfiguration()


def get_available_plugins():
    faraday_directory = os.path.dirname(os.path.realpath('faraday.py'))

    scan_path = os.path.join(faraday_directory, "bin/")

    plugin_list = os.listdir(scan_path)

    if 'fplugin' in plugin_list:
        plugin_list.remove('fplugin')

    # plugins = [plugin[:-3] for plugin in plugin_list if plugin[-3:] == '.py']

    plugin_list = filter(lambda p: p[-3:] == '.py', plugin_list)

    plugins_dic = {}

    for plugin in plugin_list:
        plugin_path = os.path.join(scan_path, plugin)

        try:
            module_fplugin = imp.load_source('module_fplugin', plugin_path)

            description = getattr(module_fplugin, '__description__', 'Empty')

            plugins_dic[plugin[:-3]] = {
                'description': description
            }

        except Exception:
            pass

    return plugins_dic


def build_faraday_plugin_command(plugin, workspace_name):
    faraday_directory = os.path.dirname(os.path.realpath('faraday.py'))
    path = os.path.join(faraday_directory, "bin")

    return 'cd "{path}" && ./fplugin -f {command}.py -u {url} -w {workspace}'.format(
        path=path,
        command=plugin,
        url=CONF.getCouchURI(),
        workspace=workspace_name
    )
