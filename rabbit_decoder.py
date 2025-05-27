#!/usr/bin/env python3
"""
RabbitMQ Password Hash Decoder
Decode RabbitMQ password hashes from Base64 format and extract salt and hash components.
"""

import sys
import binascii
import argparse
from typing import Tuple


def print_ascii_art():
    """Display ASCII art banner."""
    banner = """
██████╗  █████╗ ██████╗ ██████╗ ██╗████████╗    ██████╗ ███████╗ ██████╗ ██████╗ ██████╗ ███████╗██████╗ 
██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║╚══██╔══╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔══██╗
██████╔╝███████║██████╔╝██████╔╝██║   ██║       ██║  ██║█████╗  ██║     ██║   ██║██║  ██║█████╗  ██████╔╝
██╔══██╗██╔══██║██╔══██╗██╔══██╗██║   ██║       ██║  ██║██╔══╝  ██║     ██║   ██║██║  ██║██╔══╝  ██╔══██╗
██║  ██║██║  ██║██████╔╝██████╔╝██║   ██║       ██████╔╝███████╗╚██████╗╚██████╔╝██████╔╝███████╗██║  ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═════╝ ╚═╝   ╚═╝       ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
                                                                                                            
                            🐰 RabbitMQ Password Hash Decoder 🔓
                                        By : Mathpow                  
    """
    print(banner)


def is_valid_base64(s: str) -> bool:
    """Check if a string is valid Base64."""
    try:
        # Add padding if necessary
        missing_padding = len(s) % 4
        if missing_padding:
            s += '=' * (4 - missing_padding)
        
        # Try to decode
        binascii.a2b_base64(s)
        return True
    except (binascii.Error, ValueError):
        return False


def decode_rabbit_password_hash(password_hash: str) -> Tuple[str, str]:
    """
    Decode a RabbitMQ password hash from Base64 format.
    
    Args:
        password_hash: Base64 encoded hash string
        
    Returns:
        Tuple containing (salt, hash) as hexadecimal strings
        
    Raises:
        ValueError: If the input is not valid Base64 or has unexpected format
    """
    # Validate Base64 format
    if not is_valid_base64(password_hash):
        raise ValueError("Invalid Base64 format")
    
    try:
        # Add padding if necessary
        missing_padding = len(password_hash) % 4
        if missing_padding:
            password_hash += '=' * (4 - missing_padding)
            
        # Decode from Base64
        decoded_bytes = binascii.a2b_base64(password_hash)
        
        # Convert to hexadecimal
        hex_string = decoded_bytes.hex()
        
        # Validate minimum length (salt + some hash data)
        if len(hex_string) < 16:  # At least 8 chars for salt + some hash
            raise ValueError("Hash too short - expected at least 8 bytes")
        
        # Extract salt (first 4 bytes = 8 hex chars) and hash (remaining)
        salt = hex_string[:8]
        hash_value = hex_string[8:]
        
        return salt, hash_value
        
    except binascii.Error as e:
        raise ValueError(f"Base64 decoding failed: {e}")
    except Exception as e:
        raise ValueError(f"Unexpected error during decoding: {e}")


def display_results(salt: str, hash_value: str, original_hash: str):
    """Display formatting results in a nice format."""
    print("\n🔍 DECODE RESULTS")
    print("=" * 70)
    print(f"📝 Original Hash (Base64): {original_hash}")
    print(f"🧂 Salt (4 bytes):         {salt}")
    print(f"🔐 Hash (SHA-256):         {hash_value}")
    print(f"📏 Salt Length:            4 bytes ({len(salt)} hex chars)")
    print(f"📏 Hash Length:            {len(hash_value)//2} bytes ({len(hash_value)} hex chars)")
    print("=" * 70)


def create_argument_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="Decode RabbitMQ password hashes from Base64 format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 rabbit_decoder.py 49e6hSldHRaiYX329+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF
  python3 rabbit_decoder.py "your_base64_hash_here"
  python3 rabbit_decoder.py -q "hash_here"  # Quiet mode
  python3 rabbit_decoder.py -r "hash_here"  # Raw output
        """
    )
    
    parser.add_argument(
        "hash",
        help="Base64 encoded RabbitMQ password hash to decode"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress ASCII art banner"
    )
    
    parser.add_argument(
        "-r", "--raw",
        action="store_true",
        help="Output only raw values separated by space (salt hash)"
    )
    
    parser.add_argument(
        "-v", "--version",
        action="version",
        version="RabbitMQ Hash Decoder v1.0.0"
    )
    
    return parser


def main():
    """Main function to handle command line arguments and execute decoding."""
    parser = create_argument_parser()
    
    # Handle case where no arguments are provided
    if len(sys.argv) == 1:
        print_ascii_art()
        print("❌ Error: No hash provided\n")
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    # Display banner unless in quiet mode
    if not args.quiet and not args.raw:
        print_ascii_art()
    
    try:
        # Decode the hash
        salt, hash_value = decode_rabbit_password_hash(args.hash)
        
        # Display results based on output mode
        if args.raw:
            print(f"{salt} {hash_value}")
        else:
            display_results(salt, hash_value, args.hash)
            
    except ValueError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

