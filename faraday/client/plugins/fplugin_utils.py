'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
import imp
import os
import sys

from colorama import Fore
from faraday.utils.logs import getLogger

from faraday.config.configuration import getInstanceConfiguration

CONF = getInstanceConfiguration()
logger = getLogger()


def get_available_plugins():
    from faraday import client
    client_base_path = os.path.dirname(os.path.abspath(client.__file__))

    scan_path = os.path.join(client_base_path, "bin")
    plugin_list = os.listdir(scan_path)

    plugin_list = [
        p for p in plugin_list
        if p.endswith('.py')
        ]
    plugin_list.remove('fplugin.py')
    plugin_list.remove('__init__.py')

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
                sys.stderr.write(Fore.YELLOW +
                                 "WARNING: Plugin missing a description. Please update it! [%s]\n" % plugin +
                                 Fore.RESET)

            try:
                prettyname = getattr(module, '__prettyname__')
            except AttributeError:
                prettyname = plugin_name
                sys.stderr.write(Fore.YELLOW +
                                 "WARNING: Plugin missing a pretty name. Please update it! [%s]\n" % plugin +
                                 Fore.RESET)

            try:
                main = getattr(module, 'main')
            except AttributeError:
                main = None
                sys.stderr.write(Fore.YELLOW +
                                 "WARNING: Plugin missing a main function. Please fix it! [%s]\n" % plugin +
                                 Fore.RESET)

            plugins_dic[plugin[:-3]] = {
                'description': description,
                'prettyname': prettyname,
                'main': main
            }

        except Exception:
            logger.exception("Unable to import module %s\n" % plugin_path)

    return plugins_dic


def build_faraday_plugin_command(plugin, workspace_name, absolute_path=False):
    faraday_directory = os.path.dirname(os.path.realpath(os.path.join(__file__, "../")))
    path = os.path.join(faraday_directory, "bin/")

    return '{path}fplugin {command} -u {url} -w {workspace} '.format(
        path='"%s"' % path if absolute_path else '',
        command=plugin,
        url=CONF.getServerURI(),
        workspace=workspace_name
    )
