import hashlib
import json
import argparse
import os

def compute_hash(file_path):
    """Compute SHA-256 hash of a file."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except IOError as e:
        print(f"Error reading {file_path}: {e}")
        return None

def list_files(directory):
    """Recursively list all files in the given directory."""
    file_list = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_list.append(os.path.join(root, file))
    return file_list

def create_baseline(files_to_monitor, baseline_file_path):
    """Create baseline hash values for files."""
    baseline = {}
    for file_path in files_to_monitor:
        if not os.path.isfile(file_path):
            print(f"Skipping {file_path}: Not a regular file")
            continue
        
        file_hash = compute_hash(file_path)
        if file_hash:
            baseline[file_path] = file_hash
    
    with open(baseline_file_path, 'w') as baseline_file:
        json.dump(baseline, baseline_file, indent=4)
    print(f"Baseline created with {len(baseline)} files")

def detect_changes(baseline_file_path):
    """Detect changes by comparing current hashes with baseline and print new hash values."""
    try:
        with open(baseline_file_path, 'r') as baseline_file:
            baseline = json.load(baseline_file)
    except FileNotFoundError:
        print("Error: Baseline file not found")
        return

    changes = {
        'changed': [],
        'deleted': [],
        'errors': []
    }

    for file_path, expected_hash in baseline.items():
        if not os.path.exists(file_path):
            changes['deleted'].append(file_path)
            continue
        
        if os.path.isfile(file_path):
            current_hash = compute_hash(file_path)
            if current_hash is None:
                changes['errors'].append(file_path)
            elif current_hash != expected_hash:
                changes['changed'].append((file_path, expected_hash, current_hash))
        else:
            changes['errors'].append(f"{file_path} (no longer a regular file)")

    # Print results
    if changes['changed']:
        print("\nChanged files:")
        for f, old_hash, new_hash in changes['changed']:
            print(f" - {f}\n   Old Hash: {old_hash}\n   New Hash: {new_hash}")
    
    if changes['deleted']:
        print("\nDeleted files:")
        for f in changes['deleted']:
            print(f" - {f}")
    
    if changes['errors']:
        print("\nErrors encountered:")
        for f in changes['errors']:
            print(f" - {f}")

    if not changes['changed'] and not changes['deleted'] and not changes['errors']:
        print("\nNo changes detected")

def main():
    parser = argparse.ArgumentParser(
        description="File change monitor using cryptographic hashing (supports directories)",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '--create',
        action='store_true',
        help='Create baseline hashes for files or directories Ex: python3 FIM.py --create --baseline baseline.json /home/USERNAME'
    )
    parser.add_argument(
        '--check',
        action='store_true',
        help='Check for changes against baseline Ex:python3 FIM.py --check --baseline YOUR JSON FILE NAME.json'
    )
    parser.add_argument(
        '--baseline',
        required=True,
        help='Path to baseline file (JSON format) Ex: python3 FIM.py --create --baseline YOUR JSON FILE NAME.json /home/USERNAME'
    )
    parser.add_argument(
        'paths',
        nargs='*',
        help='List of files or directories to monitor (for use with --create)'
    )

    args = parser.parse_args()

    if args.create:
        if not args.paths:
            print("Error: Please specify files or directories to monitor when creating baseline")
            return
        
        # Build a list of files from provided paths.
        files_to_monitor = []
        for path in args.paths:
            if os.path.isdir(path):
                # If it's a directory, add all files in it.
                files_in_dir = list_files(path)
                files_to_monitor.extend(files_in_dir)
            elif os.path.isfile(path):
                files_to_monitor.append(path)
            else:
                print(f"Warning: {path} is neither a file nor a directory, skipping.")
        
        if not files_to_monitor:
            print("No valid files found to monitor.")
            return

        create_baseline(files_to_monitor, args.baseline)
    elif args.check:
        detect_changes(args.baseline)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()