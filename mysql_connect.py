from configparser import ConfigParser


def read_config_file(filename ='config.ini',section='mysql'):
    parse = ConfigParser()
    parse.read(filename)
    db = {}
    if parse.has_section(section):
        items = parse.items(section)
        for item in items:
            db[item[0]] = item[1]
    else:
        raise Exception('{0} not found in the {1} file'.format(section, filename))
    return db

