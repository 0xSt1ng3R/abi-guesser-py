import pkg_resources

from abi_guesser.lib import (
    guess_abi_encoded_data,
    guess_fragment,
)

__version__ = pkg_resources.get_distribution("abi-guesser").version
