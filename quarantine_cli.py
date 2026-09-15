"""
quarantine_cli.py

Manage DEVADARA's quarantine store (see devadara/quarantine.py). Run from
your terminal like:

    python quarantine_cli.py list                  # show everything currently quarantined
    python quarantine_cli.py restore <id>           # decrypt and move a file back to its original location
    python quarantine_cli.py restore <id> --to PATH # ...or to a different location
    python quarantine_cli.py delete <id>            # permanently erase a quarantined file (cannot be undone)

Get the <id> from `list`. "delete" is the one irreversible command here -
it asks for a typed "DELETE" confirmation (not just y/N) before doing
anything, since unlike quarantine_file() (always reversible via restore)
this cannot be undone.
"""

import argparse

from devadara.quarantine import delete_permanently, list_quarantined, restore_file


def cmd_list():
    entries = list_quarantined()
    if not entries:
        print("[INFO] Quarantine is empty.")
        return

    print(f"[INFO] {len(entries)} quarantined file(s):")
    for entry in entries:
        print()
        print(f"  id:            {entry['id']}")
        print(f"  original path: {entry['original_path']}")
        print(f"  quarantined:   {entry['quarantined_at']}")
        if entry.get("threat_name"):
            print(f"  threat:        {entry['threat_name']}")
        if entry.get("tier"):
            print(f"  tier:          {entry['tier']}")
        if entry.get("source"):
            print(f"  source:        {entry['source']}")
        if entry.get("hash"):
            print(f"  hash:          {entry['hash']}")


def cmd_restore(entry_id, restore_path):
    restore_file(entry_id, restore_path=restore_path)


def cmd_delete(entry_id):
    print("This permanently erases the quarantined file. It CANNOT be undone.")
    answer = input("Type DELETE (all caps) to confirm, or anything else to cancel: ").strip()
    if answer != "DELETE":
        print("  Cancelled - nothing was deleted.")
        return
    delete_permanently(entry_id)


def main():
    parser = argparse.ArgumentParser(description="Manage DEVADARA's quarantine store.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="Show everything currently quarantined.")

    restore_parser = subparsers.add_parser("restore", help="Decrypt and move a quarantined file back.")
    restore_parser.add_argument("id", help="Quarantine entry id (from 'list').")
    restore_parser.add_argument("--to", dest="restore_path", default=None,
                                 help="Restore to this path instead of the original location.")

    delete_parser = subparsers.add_parser("delete", help="Permanently erase a quarantined file.")
    delete_parser.add_argument("id", help="Quarantine entry id (from 'list').")

    args = parser.parse_args()

    if args.command == "list":
        cmd_list()
    elif args.command == "restore":
        cmd_restore(args.id, args.restore_path)
    elif args.command == "delete":
        cmd_delete(args.id)


if __name__ == "__main__":
    main()
