import multiprocessing
import sys

from namazu.desktop_host import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    if len(sys.argv) > 1 and sys.argv[1] == "--bundled-schemathesis":
        from schemathesis.cli import schemathesis

        sys.argv = ["schemathesis", *sys.argv[2:]]
        schemathesis()
    else:
        raise SystemExit(main())
