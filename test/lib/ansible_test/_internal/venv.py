"""Virtual environment management."""
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os

from . import types as t

from .config import (
    EnvironmentConfig,
)

from .util import (
    find_python,
    SubprocessError,
    get_available_python_versions,
    SUPPORTED_PYTHON_VERSIONS,
    display,
    remove_tree,
)

from .util_common import (
    run_command,
)


def create_virtual_environment(args,  # type: EnvironmentConfig
                               version,  # type: str
                               path,  # type: str
                               system_site_packages=False,  # type: bool
                               pip=True,  # type: bool
                               ):  # type: (...) -> bool
    """Create a virtual environment using venv or virtualenv for the requested Python version."""
    if os.path.isdir(path):
        display.info('Using existing Python %s virtual environment: %s' % (version, path), verbosity=1)
        return True

    python = find_python(version, required=False)
    python_version = tuple(int(v) for v in version.split('.'))

    if not python:
        # the requested python version could not be found
        return False

    if python_version >= (3, 0):
        # use the built-in 'venv' module on Python 3.x
        if run_venv(args, python, system_site_packages, pip, path):
            display.info('Created Python %s virtual environment using "venv": %s' % (version, path), verbosity=1)
            return True

        # something went wrong, most likely the package maintainer for the Python installation removed ensurepip
        # which will prevent creation of a virtual environment without installation of other OS packages

    # use the installed 'virtualenv' module on the Python requested version
    if run_virtualenv(args, python, python, system_site_packages, pip, path):
        display.info('Created Python %s virtual environment using "virtualenv": %s' % (version, path), verbosity=1)
        return True

    available_pythons = get_available_python_versions(SUPPORTED_PYTHON_VERSIONS)

    for available_python_version, available_python_interpreter in sorted(available_pythons.items()):
        virtualenv_version = get_virtualenv_version(args, available_python_interpreter)

        if not virtualenv_version:
            # virtualenv not available for this Python or we were unable to detect the version
            continue

        if python_version == (2, 6) and virtualenv_version >= (16, 0, 0):
            # virtualenv 16.0.0 dropped python 2.6 support: https://virtualenv.pypa.io/en/latest/changes/#v16-0-0-2018-05-16
            continue

        # try using 'virtualenv' from another Python to setup the desired version
        if run_virtualenv(args, available_python_interpreter, python, system_site_packages, pip, path):
            display.info('Created Python %s virtual environment using "virtualenv" on Python %s: %s' % (version, available_python_version, path), verbosity=1)
            return True

    # no suitable 'virtualenv' available
    return False


def run_venv(args,  # type: EnvironmentConfig
             run_python,  # type: str
             system_site_packages,  # type: bool
             pip,  # type: bool
             path,  # type: str
             ):  # type: (...) -> bool
    """Create a virtual environment using the 'venv' module. Not available on Python 2.x."""
    cmd = [run_python, '-m', 'venv']

    if system_site_packages:
        cmd.append('--system-site-packages')

    if not pip:
        cmd.append('--without-pip')

    cmd.append(path)

    try:
        run_command(args, cmd, capture=True)
    except SubprocessError as ex:
        remove_tree(path)

        if args.verbosity > 1:
            display.error(ex)

        return False

    return True


def run_virtualenv(args,  # type: EnvironmentConfig
                   run_python,  # type: str
                   env_python,  # type: str
                   system_site_packages,  # type: bool
                   pip,  # type: bool
                   path,  # type: str
                   ):  # type: (...) -> bool
    """Create a virtual environment using the 'virtualenv' module."""
    cmd = [run_python, '-m', 'virtualenv']

    if run_python != env_python:
        cmd += ['--python', env_python]

    if system_site_packages:
        cmd.append('--system-site-packages')

    if not pip:
        cmd.append('--no-pip')

    cmd.append(path)

    try:
        run_command(args, cmd, capture=True)
    except SubprocessError as ex:
        remove_tree(path)

        if args.verbosity > 1:
            display.error(ex)

        return False

    return True


def get_virtualenv_version(args, python):  # type: (EnvironmentConfig, str) -> t.Optional[t.Tuple[int, ...]]
    """Get the virtualenv version for the given python intepreter, if available."""
    try:
        return get_virtualenv_version.result
    except AttributeError:
        pass

    get_virtualenv_version.result = None

    cmd = [python, '-m', 'virtualenv', '--version']

    try:
        stdout = run_command(args, cmd, capture=True)[0]
    except SubprocessError as ex:
        if args.verbosity > 1:
            display.error(ex)

        stdout = ''

    if stdout:
        # noinspection PyBroadException
        try:
            get_virtualenv_version.result = tuple(int(v) for v in stdout.strip().split('.'))
        except Exception:  # pylint: disable=broad-except
            pass

    return get_virtualenv_version.result
