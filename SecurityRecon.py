import sys


def print_logo():
    logo = """
 ______  _______ _______ _______ _______ _______ ______
(  ____ |  ____ |  ___  |  ____ (  ____ |  ___  |       )
| (    )| (    )| (   ) | (    \/ (    )| (   ) | () () |
| (____)| (____)| |   | | |     | (____)| (___) | || || |
|  _____)     __) |   | | | ____|     __)  ___  | |(_)| |
| (     | (\ (  | |   | | | \_  ) (\ (  | (   ) | |   | |
| )     | ) \ \_| (___) | (___) | ) \ \_| )   ( | )   ( |
|/      |/   \__(_______|_______)/   \__//     \|/     \|
          """
    print(logo)

def menu():

    while True:
        print_logo()
        print("\nMenu:")
        print("1. Manage CVEs")
        print("2. Upload CVEs to DB")
        print("3. Manage CWEs")
        print("4. Train Model")
        print("5. Query Model")
        print("6. Exit")

        choice = input("Enter your choice (1-6): ")

        if choice == '1':
            import cvemngmt 
            cvemngmt.main()

        elif choice == '2':
            import cvedbupload
            cvedbupload.main()


        elif choice == '3':
            import cwedbupload
            cwedbupload.main()

        elif choice == '4':
            import cvetrain
            cvetrain.main()

        elif choice == '5':
            import modelquery
            modelquery.main()


        elif choice == '6':
            print("Exiting...")
            sys.exit()

    else:
        print("Invalid choice. Please enter a number between 1 and 28.")

def main():
    if len(sys.argv) < 2:
        menu()
    else:
        print("Command-line arguments detected. Please use the menu option.")

if __name__ == '__main__':
    main()
