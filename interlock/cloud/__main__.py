"""Run the cloud control plane: ``python -m interlock.cloud``.

The ASGI server (``uvicorn``) is part of the optional ``cloud`` extra and is
imported only after the command line has been parsed and validated, so
``python -m interlock.cloud --help`` works on an interpreter with no
third-party packages installed.
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .config import CloudConfig, ConfigError
from .db import INSTALL_HINT

#: A public bind without TLS termination is a misconfiguration.
PUBLIC_HOST = "0.0.0.0"


def main(argv: Optional[List[str]] = None) -> int:
    try:
        defaults = CloudConfig.from_env()
    except ConfigError as exc:
        # A malformed environment is a usage error, not a crash: report it the
        # same way a bad flag is reported, with exit 2 and no traceback.
        sys.stderr.write("interlock cloud: {}\n".format(exc))
        return 2
    parser = argparse.ArgumentParser(
        prog="python -m interlock.cloud",
        description="Run the interlock cloud control plane.",
    )
    parser.add_argument("--host", default=defaults.bind_host, metavar="ADDR",
                        help="bind address (default: %(default)s)")
    parser.add_argument("--port", type=int, default=defaults.bind_port,
                        metavar="PORT",
                        help="bind port (default: %(default)s)")
    parser.add_argument("--dsn", default=defaults.dsn, metavar="DSN",
                        help="Postgres connection string")
    parser.add_argument("--public-url", dest="public_url",
                        default=defaults.public_url, metavar="URL",
                        help="public https:// URL, required for a 0.0.0.0 bind")
    parser.add_argument("--log-level", dest="log_level",
                        default=defaults.log_level, metavar="LEVEL",
                        help="log threshold (default: %(default)s)")
    args = parser.parse_args(argv)

    config = CloudConfig(
        dsn=args.dsn,
        bind_host=args.host,
        bind_port=args.port,
        public_url=args.public_url,
        session_secret=defaults.session_secret,
        log_level=args.log_level,
        state_dir=defaults.state_dir,
    )
    if config.bind_host == PUBLIC_HOST and not config.public_url.startswith("https://"):
        sys.stderr.write(
            "interlock cloud: --host 0.0.0.0 requires --public-url https://...\n"
        )
        return 2
    try:
        config.validate()
    except ConfigError as exc:
        sys.stderr.write("interlock cloud: {}\n".format(exc))
        return 2

    try:
        import uvicorn
    except ImportError:
        sys.stderr.write("interlock cloud: {}\n".format(INSTALL_HINT))
        return 2

    from .app import CloudApp
    from .log import configure

    configure(config.log_level)
    uvicorn.run(CloudApp(config), host=config.bind_host, port=config.bind_port,
                log_level=config.log_level)
    return 0


if __name__ == "__main__":
    sys.exit(main())
