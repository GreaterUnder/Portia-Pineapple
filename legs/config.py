"""
Used to aquire and update information from the config file
"""

CONFIG_FILE="config.ini"

def setpath(function):
    """
    Decorator used to preserve the path while working with the config file
    """

    from functools import wraps
    @wraps(function)
    def wrapper(*args, **kwargs):
        from os.path import dirname
        from os import chdir, getcwd

        lwd = getcwd()
        chdir(dirname(dirname(__file__)))
        returned = function(*args, **kwargs)
        chdir(lwd)
        return returned
    return wrapper

@setpath
def load(config_file=CONFIG_FILE):
    """
    Used to load configuration from a file
    returns a configparser object
    optional str(path) to config file argument
    """

    import configparser
    configer = configparser.ConfigParser()
    configer.read(config_file)

    return configer

@setpath
def dump(configer, config_file=CONFIG_FILE):
    """
    Writes the configer object to a file
    requires a configparser object
    optional str(path) to config file argument
    no return value
    """

    with open(config_file, "w") as fout:
        configer.write(fout)

def arg_config(sysargs, config_file=CONFIG_FILE):
    """
    Used to programicaly assign different cli arguments to overwrite what came from the config file
    Requires sys.argv list
    optional str(path) to config file argument
    returns configparser object
    """

    if sysargs[0].endswith(".py"):
        sysargs = sysargs[1:]

    configer = load(config_file)
    configer.add_section("Extra")

    for argument in sysargs:
        #assignment option
        if "=" in argument:
            arg, val = argument.split("=")
            arg = arg.strip()
            val = val.strip()
        #Switch option
        else:
            arg = argument.strip()
            val = 'True'

        for header in configer.sections():
            if configer.has_option(header, arg):
                configer[header][arg] = val
                break

            if header == "Extra":
                configer["Extra"][arg] = val

    if len(configer['Extra']):
        if not configer['Extra'].getboolean("allow_extra", False):
            print("extra options '{}' assigned without explicet assignment of 'allow_extra'".format(
                ", ".join([_ for _ in configer['Extra'].keys()])))
            print("All extra options will be ignored")
            configer.pop('Extra')

    return configer

#TODO
# Generate default configparser object
# Used in case no config present
#  NOT used when asked to load a non-default config file
