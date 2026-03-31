from importlib.resources import files


def get_resource(filename):
    return str(files(__package__).joinpath('data', filename))
