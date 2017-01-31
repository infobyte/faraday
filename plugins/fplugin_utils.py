import imp
import os
from colorama import Fore

from config.configuration import getInstanceConfiguration

CONF = getInstanceConfiguration()


def get_available_plugins():
    faraday_directory = os.path.dirname(os.path.realpath(os.path.join(__file__, "../")))

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

            plugin_name = os.path.splitext(plugin)[0]

            module = imp.load_source('module_fplugin_%s' % plugin_name, plugin_path)

            try:
                description = getattr(module, '__description__')
            except AttributeError:
                description = 'Empty'
                print (Fore.YELLOW +
                       "WARNING: Plugin missing a description. Please update it! [%s.py]" % plugin +
                       Fore.RESET)

            try:
                prettyname = getattr(module, '__prettyname__')
            except AttributeError:
                prettyname = plugin_name
                print (Fore.YELLOW +
                       "WARNING: Plugin missing a pretty name. Please update it! [%s.py]" % plugin +
                       Fore.RESET)

            plugins_dic[plugin[:-3]] = {
                'description': description,
                'prettyname': prettyname
            }

        except Exception:
            print "Unable to import module %s" % plugin_path

    return plugins_dic


def build_faraday_plugin_command(plugin, workspace_name):
    faraday_directory = os.path.dirname(os.path.realpath(os.path.join(__file__, "../")))
    path = os.path.join(faraday_directory, "bin")

    return '"{path}/fplugin" -f {command} -u {url} -w {workspace}'.format(
        path=path,
        command=plugin,
        url=CONF.getCouchURI(),
        workspace=workspace_name
    )
