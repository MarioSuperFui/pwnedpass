import dearpygui.dearpygui as dpg
import hashlib
import requests

# Function to request data from the "Have I Been Pwned" API
def request_api_data(query_char):
    url = f'https://api.pwnedpasswords.com/range/{query_char}'
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, check the API and try again')
    return res

# Function to parse the response and check for password leaks
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

# Function to check the password against the API
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

# DearPyGui Callback function when the "Check Password" button is clicked
def check_password(sender, app_data):
    password = dpg.get_value("password_input")  # Get value from the input field
    try:
        count = pwned_api_check(password)
        if count:
            dpg.set_value("result_text", f"The password was found {count} times! You should change it.")
        else:
            dpg.set_value("result_text", "The password was NOT found. It's safe to use.")
    except Exception as e:
        dpg.set_value("result_text", f"Error: {e}")

# Set up DearPyGui window and widgets
dpg.create_context()

with dpg.handler_registry():
    # Add window for password checking
    with dpg.window(label="Password Checker", width=400, height=300):
        dpg.add_input_text(tag="password_input", label="Enter Password", password=True)
        dpg.add_button(label="Check Password", callback=check_password)
        dpg.add_text(tag="result_text", default_value="")

# Show the DearPyGui viewport and start the GUI event loop
dpg.create_viewport(title='Password Checker', width=400, height=300)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.start_dearpygui()

# Clean up after the GUI loop ends
dpg.destroy_context()
