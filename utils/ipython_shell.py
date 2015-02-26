'''
Faraday Penetration Test IDE
Copyright (C) 2013  Infobyte LLC (http://www.infobytesec.com/)
See the file 'doc/LICENSE' for the license information

'''
"""
This module contains some useful functions to embedd an IPython shell.
This allows to interactively test things.
TODO: create a QT Widget capable of running the IPython shell whitout
blocking the entire app. Kind of the http://ipython.scipy.org/moin/Cookbook/EmbeddingInGTK
"""

import traceback
import model.api

IPYTHON_BANNER = "\n".join(["-"*45,
                          "Starting embedded IPython Shell...",
                          "Press CTRL + D to exit.",
                          "-"*45])

IPYTHON_EXIT_MSG = "\n".join(["-"*45,
                          "Exiting IPython Shell...",
                          "Returning normal execution.",
                          "-"*45])

__ipython_active = False

                                                               
                                                                           

def embedd_ipython011(local_ns={}, global_ns={}):
    from IPython.config.loader import Config
    from IPython.frontend.terminal.embed import InteractiveShellEmbed
    cfg = Config()    
    ipshell = InteractiveShellEmbed(config=cfg,
                                    banner1 = IPYTHON_BANNER,
                                    exit_msg = IPYTHON_EXIT_MSG)
                         
    ipshell(local_ns=local_ns, global_ns=global_ns)


def embedd_ipython010(local_ns={}, global_ns={}):
    from IPython.Shell import IPShellEmbed
    ipshell = IPShellEmbed( [""],
                            banner = IPYTHON_BANNER,
                            exit_msg = IPYTHON_EXIT_MSG
                          )
    ipshell(local_ns=local_ns, global_ns=global_ns)
    

def embedd(local_ns={}, global_ns={}):
    global __ipython_active
    if __ipython_active:
        return

    __ipython_active = True
    try:
        import IPython
        version = IPython.__version__.split(".")[1]
        if int(version) > 10:
            embedd_ipython011(local_ns, global_ns)
        else:
            embedd_ipython010(local_ns, global_ns)
            
    except Exception, e:
        msg = "An error ocurred while trying to embedd the IPython Shell\n%s"
        model.api.log(msg % str(e), "ERROR")
        model.api.devlog(msg % traceback.format_exc())
    finally:
        __ipython_active = False


def embeddQT(local_ns={}, global_ns={}):
                                             

    global __ipython_active
    if __ipython_active:
        return
    __ipython_active = True
    try:
        from IPython.Shell import IPShellQt
        ipshell = IPShellQt( [""],
                                user_ns=local_ns,
                                user_global_ns=global_ns
                              )
        ipshell.run()
    except Exception:
        model.api.devlog("An error ocurred while trying to embedd the IPython Shell\n%s" % traceback.format_exc())
    finally:
        __ipython_active = False
