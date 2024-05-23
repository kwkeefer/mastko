from argparse import ArgumentParser, Namespace, _SubParsersAction

from mastko.data.target import Target
from mastko.lib.bruteforcer import Bruteforcer
from mastko.lib.exceptions import BruteforceCommandException
from mastko.lib.logger import get_logger

log = get_logger("mastko.cli.commands.bruteforce")


def bruteforce_parser(subparser: _SubParsersAction) -> None:
    bruteforce_parser: ArgumentParser = subparser.add_parser(
        name="bruteforce", help="runs subdomain takeover bruteforce service"
    )
    bruteforce_parser.add_argument(
        "-i",
        "--iterations",
        help="Specify the number of bruteforce iterations",
        metavar="iterations",
        dest="iterations",
        type=int,
        required=True,
    )


def bruteforce_executer(args: Namespace) -> None:
    log.info(f"Initiating bruteforce for {args.iterations} iterations")

    if not Target.target_available():
        raise BruteforceCommandException(
            "Prequisite for bruteforce not met, there are no targets available in DB. "
            "Please run `mastko validate_targets --help` for more infromation."
        )

    bruteforcer = Bruteforcer(targets=Target.get_all_targets_from_db())
    bruteforcer.run(iterations=args.iterations)
