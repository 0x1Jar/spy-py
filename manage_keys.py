#!/usr/bin/env python3
import argparse
from sub_finder.config import Config


def main():
    parser = argparse.ArgumentParser(description="Manage API keys for subdomain finder")
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Add key command
    add_parser = subparsers.add_parser('add', help='Add an API key')
    add_parser.add_argument('service', choices=['google', 'bing'], help='Service name')
    add_parser.add_argument('key', help='API key')
    add_parser.add_argument('--cx', help='Google Custom Search Engine ID (required for Google)')

    # Remove key command
    remove_parser = subparsers.add_parser('remove', help='Remove an API key')
    remove_parser.add_argument('service', choices=['google', 'bing'], help='Service name')

    # List keys command
    subparsers.add_parser('list', help='List all API keys')

    args = parser.parse_args()
    config = Config()

    if args.command == 'add':
        additional_params = {}
        if args.service == 'google' and not args.cx:
            print("Error: Google Custom Search Engine ID (--cx) is required for Google API")
            return
        elif args.service == 'google':
            additional_params['cx'] = args.cx

        config.set_api_key(args.service, args.key, additional_params)
        print(f"Added {args.service} API key successfully")

    elif args.command == 'remove':
        config.remove_api_key(args.service)
        print(f"Removed {args.service} API key successfully")

    elif args.command == 'list':
        keys = config.list_api_keys()
        if not keys:
            print("No API keys configured")
        else:
            for service, details in keys.items():
                print(f"\n{service.upper()}:")
                for key, value in details.items():
                    print(f"  {key}: {value}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()