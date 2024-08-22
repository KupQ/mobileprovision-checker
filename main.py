import sys
from cert_checker import check

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <mobileprovision_file_path>")
        sys.exit(1)

    mobileprovision_path = sys.argv[1]
    check(mobileprovision_path)

if __name__ == '__main__':
    main()
