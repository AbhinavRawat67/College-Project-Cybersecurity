def Caesar_Cipher():
    Password = input("Enter password: ")
    Encrypted_Password = ""

    for i in Password:
        if i.isalpha():
            Ascii = ord(i)
            # Uppercase
            if 'A' <= i <= 'Z':
                E = chr((Ascii - 65 + 3) % 26 + 65)
            # Lowercase
            else:
                E = chr((Ascii - 97 + 3) % 26 + 97)
        else:
            E = i

        Encrypted_Password += E

    print(f"Encrypted Password is: {Encrypted_Password}")


def ROT13():
    Password = input("Enter password you want to encrypt: ")
    Encrypted_Password = ""

    for i in Password:
        if i.isalpha():
            Ascii = ord(i)
            # Uppercase
            if 'A' <= i <= 'Z':
                E = chr((Ascii - 65 + 13) % 26 + 65)
            # Lowercase
            else:
                E = chr((Ascii - 97 + 13) % 26 + 97)
        else:
            E = i

        Encrypted_Password += E

    print(f"Encrypted Password is: {Encrypted_Password}")


# -------------------- MENU --------------------
while True:
    print("\n--- Encryption Menu ---")
    print("1. Caesar Cipher (+3)")
    print("2. ROT13")
    print("3. Exit")
    
    choice = input("Enter your choice (1/2/3): ")

    if choice == "1":
        Caesar_Cipher()
    elif choice == "2":
        ROT13()
    elif choice == "3":
        print("Exiting program.")
        break
    else:
        print("Invalid choice, try again.")
        continue

    # Continue option
    cont = input("\nWould you like to continue? (y/n): ").lower()
    if cont != "y":
        print("Exiting program.")
        break
