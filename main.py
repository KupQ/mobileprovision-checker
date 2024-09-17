import sys
from utils.p12_utils import change_p12_password
from utils.certificate_utils import check_certificates

def main():
    if len(sys.argv) == 5:
        change_p12_password(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
    elif len(sys.argv) == 3 and sys.argv[1].endswith('.p12'):
        check_certificates(p12_path=sys.argv[1], password=sys.argv[2])
    elif len(sys.argv) == 2:
        if sys.argv[1].endswith('.p12'):
            check_certificates(p12_path=sys.argv[1])
        elif sys.argv[1].endswith('.mobileprovision'):
            check_certificates(mobileprovision_path=sys.argv[1])
        else:
            print("Unsupported file type. Please provide a .mobileprovision or .p12 file.")
            sys.exit(1)
    else:
        print("Usage:")
        print("To check a certificate: python3 main.py file.p12 [password] or file.mobileprovision")
        print("To change p12 password: python3 main.py file.p12 oldpassword newpassword newfile.p12")
        sys.exit(1)

if __name__ == '__main__':
    main()
