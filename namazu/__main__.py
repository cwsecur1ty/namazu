import argparse
import uvicorn


def main():
    parser = argparse.ArgumentParser(description="Namazu - standalone API testing by K9")
    parser.add_argument("--host", default="127.0.0.1", help="Listen address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8010, help="Listen port (default: 8010)")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    print(f"Namazu: http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}")
    uvicorn.run("namazu.app:app", host=args.host, port=args.port, access_log=False)


if __name__ == "__main__":
    main()
