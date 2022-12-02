#!/usr/bin/python3
import shutil

import channel



def show_header():
    width = shutil.get_terminal_size()[0]
    print("C2 Interface v0.1".center(width, " "))
    print("-".center(width, "-"))


def main_menu():
    show_header()
    print("\nMain Menu:\n")
    print("1) Test Connection to Bot")
    print("2) Show Host Information")
    print("3) Run Command")
    print("4) Danger Zone")
    print("5) Exit")
    match input("\n Please Select an Option: "):
        case "1":
            test_conn()
        case "2":
            show_info()
        case "3":
            arbitrary_exec()
        case "4":
            danger_menu()
        case "5":
            print("\n\nGoodbye.\n")
            exit()
        case _:
            print("Bad input! Please enter a number from 1 to 5. \n\n")
            main_menu()


def test_conn():
    pass


def show_info():
    pass


def arbitrary_exec():
    pass


def danger_menu():
    pass


def send(payload: str):
    pass


main_menu()
