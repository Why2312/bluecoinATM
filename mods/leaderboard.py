
import PySimpleGUI as sg
from bs4 import BeautifulSoup
import requests
from mods.leaderboard_data.parser import parse_leaderboard as parse
import time
import threading
global mod_data

global thread
global event

event = threading.Event()
thread = None
mod_data = {
    "name": "Leaderboard",
    "author": "GenericRblxStudioDev",
    "version": "1.1",
    "description": "This mod adds a leaderboard tab to the main window.",
    "dependencies": [],
    "load": "main",
    "uicreated": "onuicreated",
    "aftercreation": "after_creation",
    "shutdown": "shutdown",
    "uishutdown": "shutdown" # We want to stop the thread in each of these either way
}
global print

global leaderboard_data

def shutdown(atm):
    global thread
    global event
    event.clear()

def on_double_click(event, values, atm):
    if event != "leaderDoubleClicked":
        return False # Don't stop execution
    # Display a popup with the user's data
    global leaderboard_data
    window = atm.get_window()
    # Is user selected?
    if len(values['leader']) == 0:
        return False # Don't stop execution
    # Get the selected user
    selected = window['leader'].get()[0]
    
    # Get the user's data
    for tuple in leaderboard_data:
        # Get everything except the bluecoin count (eg: before " -", including the space)
        new_selected = selected.split(" -")[0]
        if tuple[1] == new_selected:
            selected = tuple
            break
    # Multiline string
    # 1 bluecoin = 100K morsels
    text = f"""Username: {selected[1]}
Bluecoins: {int(selected[2]) / 100000}
Morsels: {int(selected[2])}
Share: {selected[3]}%"""

    sg.popup(text, title="User data", non_blocking=True)
    return True # Stop execution


def update_list(eventr, values, atm):
    global thread
    global event
    if not thread.is_alive():
        event.set()
        thread = threading.Thread(target=update_thread, args=(atm,event))
        thread.start()
    global leaderboard_data
    if eventr != "leaderupdate":
        return False  # Don't stop execution

    window = atm.get_window()
    listdata = values["leaderupdate"]
    # Get the amount of entries
    listbox = window['leader'].Widget
    current_view = listbox.yview()
    current_selection = values['leader']

    leaderboard_data = listdata
    leaderboard = [f"{tuple[1]} - {format(int(tuple[2]) / 100000, '.5f')}" for tuple in listdata]
    
    # Check if any element in leaderboard is past 60 characters in length
    for index, item in enumerate(leaderboard):
        if len(item) > 60:
            leaderboard[index] = None # trolled!!
    window['leadercount'].update(f"{len(leaderboard)}")

    # Update the listbox
    window['leader'].update(leaderboard)
    listbox.yview_moveto(current_view[0])

    # Reselect and refresh the ListBox
    if current_selection:
        try:
            selected_index = leaderboard.index(current_selection[0])
            window['leader'].update(set_to_index=selected_index, select_mode=sg.LISTBOX_SELECT_MODE_SINGLE)
        except ValueError:
            pass  # Previously selected item no longer exists

    return True
    
def onuicreated(atm, layoutdata):
    default_ui = atm.get_ui_settings()
    defaultfont = default_ui["Normal"]["Font"]
    titlefont = default_ui["Title"]["Font"]
    ui = [
    [sg.Text('', expand_x=True),sg.Text("Leaderboard", font=titlefont, justification="center"), sg.Text('', expand_x=True)],
    [sg.Text('Entries: ', font=defaultfont), sg.Text('', expand_x=True, key='leadercount', font=defaultfont), sg.Text('', expand_x=True)],
    # LISTBOX, without horizontal scrolling
    [sg.Listbox(list({}), size=(60, 15), key='leader', select_mode=sg.LISTBOX_SELECT_MODE_SINGLE, enable_events=True, bind_return_key=True, font=defaultfont, tooltip="Double click to view user data", )],
    ]
    # Set as last tab
    index = 4 # Probably not the best way to do this, but it works
    atm.add_layout("Leaderboard", [index, ui])

def after_creation(atm):
    global thread
    global event
    event.clear()
    if thread:
        thread.join()
    # Get the window, bind the list as a double click handler
    window = atm.get_window()
    window['leader'].bind('<Double-Button-1>', 'DoubleClicked')
    event.set()
    thread = threading.Thread(target=update_thread, args=(atm,event))
    thread.start()


def update_thread(atm, event):
    window = atm.get_window()
    while event.is_set():
        # Send a request
        url = "https://darkbluestealth.pythonanywhere.com/leaderboard"
        leaderboard_data = parse(url)
        # Call our update_list function, using window
        if event.is_set():
            window.write_event_value("leaderupdate", leaderboard_data)
        else:
            print("Event is not set, stopping thread")
            break
        time.sleep(2.5)
    

    

def main(atm):
    global print
    print = atm.print
    # Attach a handler to the refresh button
    print("Leaderboard mod loaded!")
    atm.addHandler("leaderDoubleClicked", on_double_click)
    atm.addHandler("leader", lambda event, values, atm: False) # We dont want to do anything with this event, but we need to handle it
    atm.addHandler("leaderupdate", update_list)
    