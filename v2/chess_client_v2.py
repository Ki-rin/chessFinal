import pygame
import pygame_gui
import socket
import json
import threading
import sys
import os
import hashlib
import secrets
from enum import Enum
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Initialize Pygame
pygame.init()

# Constants
BOARD_SIZE = 9
CELL_SIZE = 60
BOARD_WIDTH = BOARD_SIZE * CELL_SIZE
BOARD_HEIGHT = BOARD_SIZE * CELL_SIZE
SIDEBAR_WIDTH = 300
WINDOW_WIDTH = BOARD_WIDTH + SIDEBAR_WIDTH
WINDOW_HEIGHT = max(BOARD_HEIGHT, 600)

# Colors
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
LIGHT_BROWN = (240, 217, 181)
DARK_BROWN = (181, 136, 99)
HIGHLIGHT_COLOR = (255, 255, 0, 128)
VALID_MOVE_COLOR = (0, 255, 0, 128)
SELECTED_COLOR = (255, 0, 0, 128)
CHECK_COLOR = (255, 100, 100)
BUTTON_COLOR = (70, 130, 180)
BUTTON_HOVER = (100, 149, 237)
TEXT_COLOR = (50, 50, 50)


class GameState(Enum):
    LOGIN = "login"
    REGISTER = "register"
    PASSWORD_RESET = "password_reset"
    MENU = "menu"
    WAITING = "waiting"
    PLAYING = "playing"
    GAME_END = "game_end"


class CryptoManager:
    """Handles Diffie-Hellman key exchange and AES encryption/decryption"""

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        self.aes_key = None
        self.dh_prime = None
        self.dh_generator = None
        self.authenticated = False
        self.username = None

        # GUI Manager for text input
        self.gui_manager = pygame_gui.UIManager((WINDOW_WIDTH, WINDOW_HEIGHT))

        # Login/Register fields
        self.username_input = None
        self.password_input = None
        self.email_input = None
        self.confirm_password_input = None
        self.reset_code_input = None
        self.new_password_input = None

        # Buttons
        self.login_button = None
        self.register_button = None
        self.switch_to_register_button = None
        self.switch_to_login_button = None
        self.password_reset_button = None
        self.send_reset_button = None
        self.confirm_reset_button = None
        self.back_to_login_button = None

        # Start in login state
        self.state = GameState.LOGIN

    def set_dh_parameters(self, prime, generator):
        """Set DH parameters received from server"""
        self.dh_prime = int(prime)
        self.dh_generator = int(generator)

    def generate_dh_keypair(self):
        """Generate DH private and public keys"""
        if self.dh_prime is None or self.dh_generator is None:
            raise ValueError("DH parameters not set")

        self.private_key = secrets.randbelow(self.dh_prime - 2) + 1
        self.public_key = pow(self.dh_generator, self.private_key, self.dh_prime)
        return self.public_key

    def compute_shared_secret(self, other_public_key):
        """Compute shared secret from other party's public key"""
        if self.private_key is None:
            raise ValueError("Must generate keypair first")

        self.shared_secret = pow(other_public_key, self.private_key, self.dh_prime)

        # Derive AES key from shared secret using SHA-256
        shared_bytes = self.shared_secret.to_bytes(256, byteorder='big')
        self.aes_key = hashlib.sha256(shared_bytes).digest()[:32]  # 256-bit key

        return self.shared_secret

    def encrypt_message(self, plaintext):
        """Encrypt message using AES-CBC"""
        if self.aes_key is None:
            raise ValueError("Must establish shared secret first")

        # Convert to bytes if string
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Generate random IV
        iv = os.urandom(16)

        # Pad the plaintext
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext)
        padded_data += padder.finalize()

        # Encrypt
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Return IV + ciphertext
        return iv + ciphertext

    def decrypt_message(self, encrypted_data):
        """Decrypt message using AES-CBC"""
        if self.aes_key is None:
            raise ValueError("Must establish shared secret first")

        # Extract IV and ciphertext
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # Decrypt
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext)
        plaintext += unpadder.finalize()

        return plaintext.decode('utf-8')


class SecureChessClient:
    def __init__(self):
        # Game loop control
        self.running = True

        # Initialize Pygame display
        self.screen = pygame.display.set_mode((WINDOW_WIDTH, WINDOW_HEIGHT))
        pygame.display.set_caption("Secure Chess 9x9 Online")
        self.clock = pygame.time.Clock()

        # Network state
        self.socket = None
        self.connected = False
        self.secure = False

        # Crypto manager
        self.crypto = CryptoManager()

        # Authentication state
        self.authenticated = False
        self.username = None

        # Core game state
        self.state = GameState.LOGIN  # Start with login
        self.board = [[None for _ in range(9)] for _ in range(9)]
        self.selected_piece = None
        self.valid_moves = []
        self.current_player = "white"
        self.player_color = None
        self.game_id = None

        # Game status flags
        self.in_check = False
        self.game_end_message = ""
        self.game_end_timer = 0
        self.last_move_time = 0
        self.stuck_check_timer = 0

        # Promotion handling
        self.promotion_pending = False
        self.promotion_move = None
        self.promotion_options = ['queen', 'rook', 'bishop', 'knight']

        # UI fonts
        self.font = pygame.font.Font(None, 24)
        self.title_font = pygame.font.Font(None, 48)
        self.small_font = pygame.font.Font(None, 18)
        self.large_font = pygame.font.Font(None, 36)

        # Message system
        self.messages = []
        self.max_messages = 10

        # Initialize piece sprites
        self.piece_sprites = {}
        self.load_piece_sprites()

        # Try to initialize GUI components
        try:
            import pygame_gui
            self.gui_manager = pygame_gui.UIManager((WINDOW_WIDTH, WINDOW_HEIGHT))

            # Initialize UI element references as None
            self.username_input = None
            self.password_input = None
            self.email_input = None
            self.confirm_password_input = None
            self.reset_code_input = None
            self.new_password_input = None
            self.login_button = None
            self.register_button = None
            self.switch_to_register_button = None
            self.switch_to_login_button = None
            self.password_reset_button = None
            self.send_reset_button = None
            self.confirm_reset_button = None
            self.back_to_login_button = None

            # Setup login UI
            self.setup_login_ui()

        except ImportError:
            print("❌ pygame_gui required for login system")
            print("Installing pygame_gui...")
            import subprocess
            import sys
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "pygame_gui"])
                print("✅ Installed pygame_gui. Please restart the client.")
                sys.exit(0)
            except:
                print("❌ Install failed. Run: pip install pygame_gui")
                sys.exit(1)

    def setup_login_ui(self):
        """Setup login UI elements"""
        self.clear_ui()

        # Username field
        self.username_input = pygame_gui.elements.UITextEntryLine(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 150, 200, 300, 35),
            manager=self.gui_manager,
            placeholder_text="Username"
        )

        # Password field
        self.password_input = pygame_gui.elements.UITextEntryLine(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 150, 250, 300, 35),
            manager=self.gui_manager,
            placeholder_text="Password"
        )
        self.password_input.set_text_hidden(True)

        # Login button
        self.login_button = pygame_gui.elements.UIButton(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 75, 300, 150, 40),
            text="Login",
            manager=self.gui_manager
        )

        # Switch to register button
        self.switch_to_register_button = pygame_gui.elements.UIButton(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 100, 350, 200, 35),
            text="Create Account",
            manager= self.gui_manager
        )

        # Password reset button
        self.password_reset_button = pygame_gui.elements.UIButton(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 100, 395, 200, 35),
            text="Forgot Password",
            manager= self.gui_manager
        )

    def setup_register_ui(self):
        """Setup registration UI elements"""
        self.clear_ui()

        # Username field
        self.username_input = pygame_gui.elements.UITextEntryLine(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 150, 180, 300, 35),
            manager=self.gui_manager,
            placeholder_text="Username (min 3 characters)"
        )

        # Email field
        self.email_input = pygame_gui.elements.UITextEntryLine(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 150, 225, 300, 35),
            manager=self.gui_manager,
            placeholder_text="Email"
        )

        # Password field
        self.password_input = pygame_gui.elements.UITextEntryLine(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 150, 270, 300, 35),
            manager=self.gui_manager,
            placeholder_text="Password (min 6 characters)"
        )
        self.password_input.set_text_hidden(True)

        # Confirm password field
        self.confirm_password_input = pygame_gui.elements.UITextEntryLine(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 150, 315, 300, 35),
            manager=self.gui_manager,
            placeholder_text="Confirm Password"
        )
        self.confirm_password_input.set_text_hidden(True)

        # Register button
        self.register_button = pygame_gui.elements.UIButton(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 75, 365, 150, 40),
            text="Register",
            manager=self.gui_manager
        )

        # Back to login button
        self.switch_to_login_button = pygame_gui.elements.UIButton(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 100, 415, 200, 35),
            text="Back to Login",
            manager=self.gui_manager
        )


    def setup_password_reset_ui(self):
        """Setup password reset UI elements"""
        self.clear_ui()

        # Email field
        self.email_input = pygame_gui.elements.UITextEntryLine(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 150, 200, 300, 35),
            manager=self.gui_manager,
            placeholder_text="Email"
        )

        # Send reset code button
        self.send_reset_button = pygame_gui.elements.UIButton(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 100, 250, 200, 40),
            text="Send Reset Code",
            manager=self.gui_manager
        )

        # Reset code field
        self.reset_code_input = pygame_gui.elements.UITextEntryLine(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 150, 310, 300, 35),
            manager=self.gui_manager,
            placeholder_text="Reset Code"
        )

        # New password field
        self.new_password_input = pygame_gui.elements.UITextEntryLine(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 150, 355, 300, 35),
            manager=self.gui_manager,
            placeholder_text="New Password"
        )
        self.new_password_input.set_text_hidden(True)

        # Confirm reset button
        self.confirm_reset_button = pygame_gui.elements.UIButton(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 100, 405, 200, 40),
            text="Reset Password",
            manager=self.gui_manager
        )

        # Back to login button
        self.back_to_login_button = pygame_gui.elements.UIButton(
            relative_rect=pygame.Rect(WINDOW_WIDTH // 2 - 100, 455, 200, 35),
            text="Back to Login",
            manager=self.gui_manager
        )

    def clear_ui(self):
        """Clear all UI elements"""
        self.gui_manager.clear_and_reset()

        # Reset all input references
        self.username_input = None
        self.password_input = None
        self.email_input = None
        self.confirm_password_input = None
        self.reset_code_input = None
        self.new_password_input = None

        # Reset all button references
        self.login_button = None
        self.register_button = None
        self.switch_to_register_button = None
        self.switch_to_login_button = None
        self.password_reset_button = None
        self.send_reset_button = None
        self.confirm_reset_button = None
        self.back_to_login_button = None

    def handle_ui_event(self, event):
        """Handle pygame_gui events"""
        if event.type == pygame_gui.UI_BUTTON_PRESSED:
            if event.ui_element == self.login_button:
                self.attempt_login()
            elif event.ui_element == self.register_button:
                self.attempt_register()
            elif event.ui_element == self.switch_to_register_button:
                self.state = GameState.REGISTER
                self.setup_register_ui()
            elif event.ui_element == self.switch_to_login_button:
                self.state = GameState.LOGIN
                self.setup_login_ui()
            elif event.ui_element == self.password_reset_button:
                self.state = GameState.PASSWORD_RESET
                self.setup_password_reset_ui()
            elif event.ui_element == self.send_reset_button:
                self.send_password_reset_request()
            elif event.ui_element == self.confirm_reset_button:
                self.attempt_password_reset()
            elif event.ui_element == self.back_to_login_button:
                self.state = GameState.LOGIN
                self.setup_login_ui()

        elif event.type == pygame_gui.UI_TEXT_ENTRY_FINISHED:
            # Handle Enter key in text fields
            if self.state == GameState.LOGIN and event.ui_element in [self.username_input, self.password_input]:
                self.attempt_login()
            elif self.state == GameState.REGISTER and event.ui_element == self.confirm_password_input:
                self.attempt_register()

    def attempt_login(self):
        """Attempt to login with entered credentials"""
        if not self.username_input or not self.password_input:
            return

        username = self.username_input.get_text().strip()
        password = self.password_input.get_text()

        if not username or not password:
            self.add_message("❌ Please enter username and password")
            return

        if self.connected and self.secure:
            self.send_encrypted_message({
                'type': 'login',
                'username': username,
                'password': password
            })
            self.add_message(f"Logging in as {username}...")
        else:
            self.add_message("Not connected to server")

    def attempt_register(self):
        """Attempt to register with entered details"""
        if not all([self.username_input, self.email_input, self.password_input, self.confirm_password_input]):
            return

        username = self.username_input.get_text().strip()
        email = self.email_input.get_text().strip()
        password = self.password_input.get_text()
        confirm_password = self.confirm_password_input.get_text()

        if not all([username, email, password, confirm_password]):
            self.add_message("❌ Please fill all fields")
            return

        if password != confirm_password:
            self.add_message("❌ Passwords don't match")
            return

        if len(username) < 3:
            self.add_message("❌ Username must be at least 3 characters")
            return

        if len(password) < 6:
            self.add_message("❌ Password must be at least 6 characters")
            return

        if '@' not in email:
            self.add_message("❌ Invalid email format")
            return

        if self.connected and self.secure:
            self.send_encrypted_message({
                'type': 'register',
                'username': username,
                'email': email,
                'password': password
            })
            self.add_message(f"Registering user {username}...")
        else:
            self.add_message("❌ Not connected to server")

    def send_password_reset_request(self):
        """Send password reset request"""
        if not self.email_input:
            return

        email = self.email_input.get_text().strip()

        if not email:
            self.add_message("❌ Please enter email")
            return

        if self.connected and self.secure:
            self.send_encrypted_message({
                'type': 'password_reset_request',
                'email': email
            })
            self.add_message(f"📧 Sending reset code to {email}...")
        else:
            self.add_message("❌ Not connected to server")

    def attempt_password_reset(self):
        """Attempt password reset with code"""
        if not all([self.email_input, self.reset_code_input, self.new_password_input]):
            return

        email = self.email_input.get_text().strip()
        code = self.reset_code_input.get_text().strip()
        new_password = self.new_password_input.get_text()

        if not all([email, code, new_password]):
            self.add_message("❌ Please fill all fields")
            return

        if len(new_password) < 6:
            self.add_message("❌ Password must be at least 6 characters")
            return

        if self.connected and self.secure:
            self.send_encrypted_message({
                'type': 'password_reset',
                'email': email,
                'code': code,
                'new_password': new_password
            })
            self.add_message("🔑 Resetting password...")
        else:
            self.add_message("❌ Not connected to server")


    def create_piece_sprite(self, piece_type, color, size=CELL_SIZE - 10):
        """Create a simple colored piece sprite programmatically"""
        sprite = pygame.Surface((size, size), pygame.SRCALPHA)

        # Define colors for pieces
        piece_color = (240, 240, 240) if color == 'white' else (40, 40, 40)
        border_color = (0, 0, 0) if color == 'white' else (200, 200, 200)

        center_x, center_y = size // 2, size // 2

        if piece_type == 'pawn':
            pygame.draw.circle(sprite, piece_color, (center_x, center_y - 5), size // 4)
            pygame.draw.rect(sprite, piece_color, (center_x - size // 6, center_y + 5, size // 3, size // 6))
            pygame.draw.circle(sprite, border_color, (center_x, center_y - 5), size // 4, 2)

        elif piece_type == 'rook':
            base_height = size // 2
            pygame.draw.rect(sprite, piece_color, (center_x - size // 4, center_y, size // 2, base_height))
            for i in range(3):
                x = center_x - size // 4 + i * size // 6
                pygame.draw.rect(sprite, piece_color, (x, center_y - size // 6, size // 8, size // 6))
            pygame.draw.rect(sprite, border_color, (center_x - size // 4, center_y, size // 2, base_height), 2)

        elif piece_type == 'knight':
            points = [
                (center_x - size // 6, center_y + size // 4),
                (center_x - size // 4, center_y),
                (center_x - size // 6, center_y - size // 4),
                (center_x + size // 6, center_y - size // 6),
                (center_x + size // 4, center_y + size // 6),
                (center_x + size // 6, center_y + size // 4)
            ]
            pygame.draw.polygon(sprite, piece_color, points)
            pygame.draw.polygon(sprite, border_color, points, 2)

        elif piece_type == 'bishop':
            pygame.draw.circle(sprite, piece_color, (center_x, center_y + 5), size // 5)
            points = [
                (center_x, center_y - size // 3),
                (center_x - size // 6, center_y),
                (center_x + size // 6, center_y)
            ]
            pygame.draw.polygon(sprite, piece_color, points)
            pygame.draw.circle(sprite, border_color, (center_x, center_y + 5), size // 5, 2)
            pygame.draw.polygon(sprite, border_color, points, 2)

        elif piece_type == 'queen':
            pygame.draw.circle(sprite, piece_color, (center_x, center_y + 5), size // 4)
            for i in range(5):
                x = center_x - size // 4 + i * size // 8
                height = size // 6 if i % 2 == 0 else size // 8
                pygame.draw.rect(sprite, piece_color, (x, center_y - size // 4, size // 16, height))
            pygame.draw.circle(sprite, border_color, (center_x, center_y + 5), size // 4, 2)

        elif piece_type == 'king':
            pygame.draw.circle(sprite, piece_color, (center_x, center_y + 5), size // 4)
            pygame.draw.rect(sprite, piece_color, (center_x - size // 12, center_y - size // 3, size // 6, size // 4))
            pygame.draw.rect(sprite, piece_color, (center_x - size // 6, center_y - size // 4, size // 3, size // 12))
            pygame.draw.circle(sprite, border_color, (center_x, center_y + 5), size // 4, 2)

        return sprite

    def load_piece_sprites(self):
        """Load or create piece sprites"""
        pieces = ['pawn', 'rook', 'knight', 'bishop', 'queen', 'king']
        colors = ['white', 'black']

        for color in colors:
            self.piece_sprites[color] = {}
            for piece in pieces:
                filename = f"assets/{color}_{piece}.png"
                if os.path.exists(filename):
                    try:
                        sprite = pygame.image.load(filename)
                        sprite = pygame.transform.scale(sprite, (CELL_SIZE - 10, CELL_SIZE - 10))
                        self.piece_sprites[color][piece] = sprite
                        continue
                    except pygame.error:
                        pass

                self.piece_sprites[color][piece] = self.create_piece_sprite(piece, color)

    def create_piece_folder_and_instructions(self):
        """Create pieces folder and instructions for adding PNG files"""
        if not os.path.exists("assets"):
            os.makedirs("assets")
            print("📁 Created 'assets' folder for PNG sprites")

    def reset_to_menu(self):
        """Reset all game state and return to menu"""
        print("🔄 Resetting to menu state")
        self.state = GameState.MENU
        self.game_end_message = ""
        self.game_end_timer = 0
        self.in_check = False
        self.selected_piece = None
        self.valid_moves = []
        self.board = [[None for _ in range(9)] for _ in range(9)]
        self.player_color = None
        self.game_id = None
        self.current_player = "white"
        self.promotion_pending = False
        self.promotion_move = None

    # Network methods
    def connect_to_server(self, host='localhost', port=8888):
        try:
            self.create_piece_folder_and_instructions()

            print(f"🔗 Connecting to {host}:{port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.connected = True

            # Perform key exchange first
            if not self.perform_key_exchange():
                self.add_message("🔒 Key exchange failed!")
                return False

            # Start message receiving thread after successful key exchange
            thread = threading.Thread(target=self.receive_messages)
            thread.daemon = True
            thread.start()

            self.add_message("Connected to secure server!")
            return True
        except Exception as e:
            self.add_message(f"❌ Connection failed: {e}")
            return False

    def perform_key_exchange(self):
        """Perform Diffie-Hellman key exchange with server"""
        try:
            print("🔑 Starting key exchange...")

            # Receive server's key exchange message
            data = self.socket.recv(4096).decode('utf-8')
            server_msg = json.loads(data)

            if server_msg.get('type') != 'key_exchange':
                print(f"❌ Unexpected server message: {server_msg}")
                return False

            # Extract DH parameters
            server_public_key = int(server_msg['server_public_key'])
            dh_prime = server_msg['dh_prime']
            dh_generator = server_msg['dh_generator']

            print("🔢 Received DH parameters, generating keypair...")

            # Set DH parameters and generate client keypair
            self.crypto.set_dh_parameters(dh_prime, dh_generator)
            client_public_key = self.crypto.generate_dh_keypair()

            # Send client's public key
            response = {
                'type': 'key_exchange_response',
                'client_public_key': str(client_public_key)
            }
            self.socket.send(json.dumps(response).encode('utf-8'))
            print("📤 Sent public key to server")

            # Compute shared secret
            self.crypto.compute_shared_secret(server_public_key)
            print("🔐 Computed shared secret")

            # Receive encrypted confirmation
            length_data = self.socket.recv(4)
            msg_length = int.from_bytes(length_data, byteorder='big')
            encrypted_confirmation = self.socket.recv(msg_length)

            # Decrypt confirmation
            decrypted_data = self.crypto.decrypt_message(encrypted_confirmation)
            confirmation = json.loads(decrypted_data)

            if confirmation.get('type') == 'key_exchange_complete':
                self.secure = True
                print("✅ Key exchange completed successfully!")
                return True
            else:
                print(f"❌ Unexpected confirmation: {confirmation}")
                return False

        except Exception as e:
            print(f"❌ Key exchange failed: {e}")
            return False

    def receive_messages(self):
        buffer = b""  # Use bytes buffer for encrypted data

        while self.connected:
            try:
                data = self.socket.recv(4096)
                if not data:
                    print("📡 No data received, connection closed")
                    break

                buffer += data

                while buffer:
                    try:
                        # For encrypted messages, we need to find message boundaries
                        # Using length prefix: 4 bytes for message length
                        if len(buffer) < 4:
                            break

                        msg_length = int.from_bytes(buffer[:4], byteorder='big')
                        if len(buffer) < 4 + msg_length:
                            break

                        encrypted_msg = buffer[4:4 + msg_length]
                        buffer = buffer[4 + msg_length:]

                        # Decrypt the message
                        if self.secure:
                            decrypted_data = self.crypto.decrypt_message(encrypted_msg)
                            message = json.loads(decrypted_data)
                        else:
                            # Fallback for unencrypted messages (shouldn't happen after key exchange)
                            message = json.loads(encrypted_msg.decode('utf-8'))

                        self.handle_server_message(message)

                    except json.JSONDecodeError:
                        if len(buffer) > 10000:
                            buffer = b""
                        break
                    except Exception as e:
                        print(f"❌ Error processing message: {e}")
                        if len(buffer) > 10000:
                            buffer = b""
                        break

            except ConnectionResetError:
                print("📡 Connection reset by server")
                break
            except ConnectionAbortedError:
                print("📡 Connection aborted by server")
                break
            except OSError as e:
                print(f"📡 Socket error: {e}")
                break
            except Exception as e:
                print(f"❌ Error receiving message: {e}")
                break

        print("📡 Message receiving loop ended")
        self.connected = False
        self.secure = False

        # If we were in a game and connection dropped, show appropriate message
        if self.state == GameState.PLAYING:
            print("⚠️ Connection lost during game")
            self.add_message("Connection lost - game may have ended")
            self.game_end_message = "Connection Lost\nReturning to menu..."
            self.game_end_timer = pygame.time.get_ticks() + 4000
            self.state = GameState.GAME_END

    def handle_server_message(self, message):
        msg_type = message.get('type')
        print(f"📨 Received message: {msg_type}")

        if msg_type == 'login_success':
            self.authenticated = True
            self.username = message.get('username')
            self.state = GameState.MENU
            self.clear_ui()
            self.add_message(f"Welcome back, {self.username}!")

        elif msg_type == 'register_success':
            self.add_message("Registration successful! Please login.")
            self.state = GameState.LOGIN
            self.setup_login_ui()

        elif msg_type == 'reset_code_sent':
            if message.get('success'):
                self.add_message("📧 Reset code sent! Check your email.")
            else:
                self.add_message(f"❌ {message.get('message', 'Reset failed')}")

        elif msg_type == 'password_reset_result':
            if message.get('success'):
                self.add_message("✅ Password reset successful! Please login.")
                self.state = GameState.LOGIN
                self.setup_login_ui()
            else:
                self.add_message(f"❌ {message.get('message', 'Reset failed')}")



        if msg_type == 'queue_joined':
            self.state = GameState.WAITING
            position = message.get('position', 0)
            self.add_message(f"Joined queue (position {position})")

        elif msg_type == 'game_start':
            print(f"🎮 Game starting: {message}")
            self.state = GameState.PLAYING
            self.game_id = message['game_id']
            self.player_color = message['color']
            self.board = message['board']
            self.current_player = message['current_player']
            self.add_message(f"Game started! You are {self.player_color}")

        elif msg_type == 'move_made':
            self.board = message['board']
            self.current_player = message['current_player']
            self.selected_piece = None
            self.valid_moves = []
            self.last_move_time = pygame.time.get_ticks()

            # Handle game status
            game_status = message.get('game_status', {})
            status = game_status.get('status', 'playing')

            if status == 'check':
                self.in_check = True
                check_color = game_status.get('in_check', 'unknown')
                self.add_message(f"⚠{check_color.title()} is in check!")
            elif status == 'checkmate':
                winner = game_status.get('winner')
                loser = game_status.get('loser')

                if winner == self.player_color:
                    self.game_end_message = f"YOU WIN!\nCheckmate!"
                elif loser == self.player_color:
                    self.game_end_message = f"YOU LOSE\nCheckmate!"
                else:
                    if self.current_player != self.player_color:
                        self.game_end_message = f"YOU WIN!\nCheckmate!"
                    else:
                        self.game_end_message = f"YOU LOSE\nCheckmate!"

                self.game_end_timer = pygame.time.get_ticks() + 4000
                self.state = GameState.GAME_END
            elif status == 'stalemate':
                self.game_end_message = f"DRAW\nStalemate!"
                self.game_end_timer = pygame.time.get_ticks() + 4000
                self.state = GameState.GAME_END
            else:
                self.in_check = False

            # Handle promotion notification
            if message.get('promotion', False):
                promoted_to = message.get('promoted_to', 'queen')
                self.add_message(f"Pawn promoted to {promoted_to}!")

            # Handle capture notification
            if message.get('captured'):
                captured_piece = message['captured']
                self.add_message(f"Captured {captured_piece['color']} {captured_piece['type']}!")

        elif msg_type == 'game_end':
            status = message['status']
            winner = message.get('winner')
            loser = message.get('loser')
            game_message = message['message']

            print(f"🏁 Game end message received: {status}")

            # Reset game state immediately
            self.selected_piece = None
            self.valid_moves = []
            self.promotion_pending = False
            self.promotion_move = None
            self.in_check = False

            if status == 'checkmate':
                if winner == self.player_color:
                    self.game_end_message = f"YOU WIN!\n{game_message}"
                elif loser == self.player_color:
                    self.game_end_message = f"YOU LOSE\n{game_message}"
                else:
                    self.game_end_message = f"Game Over\n{game_message}"
            elif status == 'stalemate':
                self.game_end_message = f"DRAW\n{game_message}"

            self.add_message(game_message)
            self.game_end_timer = pygame.time.get_ticks() + 4000
            self.state = GameState.GAME_END

        elif msg_type == 'error':
            self.add_message(f"Error: {message['message']}")

        elif msg_type == 'opponent_disconnected':
            self.add_message("Opponent disconnected")
            self.game_end_message = "Opponent Disconnected\nGame ended"
            self.game_end_timer = pygame.time.get_ticks() + 4000
            self.state = GameState.GAME_END

    def send_encrypted_message(self, message):
        """Send encrypted message to server"""
        if self.connected and self.secure:
            try:
                # Encrypt the message
                message_str = json.dumps(message)
                encrypted_data = self.crypto.encrypt_message(message_str)

                # Send with length prefix
                msg_length = len(encrypted_data)
                self.socket.send(msg_length.to_bytes(4, byteorder='big') + encrypted_data)

                print(f"📤 Sent encrypted message: {message.get('type', 'unknown')}")
                return True
            except Exception as e:
                print(f"❌ Error sending encrypted message: {e}")
                return False
        elif self.connected:
            # Fallback to unencrypted (should only happen during key exchange)
            try:
                self.socket.send(json.dumps(message).encode('utf-8'))
                return True
            except Exception as e:
                print(f"❌ Error sending unencrypted message: {e}")
                return False
        return False

    def add_message(self, text):
        self.messages.append(text)
        if len(self.messages) > self.max_messages:
            self.messages.pop(0)

    def join_queue(self):
        if self.connected and self.secure:
            self.send_encrypted_message({'type': 'join_queue'})

    # Game logic methods
    def needs_promotion(self, from_row, from_col, to_row, to_col):
        """Check if a move will result in pawn promotion"""
        piece = self.board[from_row][from_col]
        if piece and piece['type'] == 'pawn':
            promotion_row = 0 if piece['color'] == 'white' else 8
            return to_row == promotion_row
        return False

    def make_move(self, from_row, from_col, to_row, to_col, promotion_piece=None):
        if self.connected and self.secure and self.state == GameState.PLAYING:
            move_message = {
                'type': 'move',
                'from_row': from_row,
                'from_col': from_col,
                'to_row': to_row,
                'to_col': to_col
            }

            if promotion_piece:
                move_message['promotion_piece'] = promotion_piece

            self.send_encrypted_message(move_message)

    def handle_promotion_choice(self, choice):
        """Handle the player's promotion choice"""
        if self.promotion_pending and self.promotion_move:
            from_row, from_col, to_row, to_col = self.promotion_move
            self.make_move(from_row, from_col, to_row, to_col, choice)
            self.promotion_pending = False
            self.promotion_move = None

    def get_valid_moves(self, row, col):
        """Calculate valid moves for a piece based on chess rules"""
        valid_moves = []
        piece = self.board[row][col]

        if not piece:
            return valid_moves

        piece_type = piece['type']
        piece_color = piece['color']

        if piece_type == 'pawn':
            valid_moves = self._get_pawn_moves(row, col, piece_color)
        elif piece_type == 'rook':
            valid_moves = self._get_rook_moves(row, col, piece_color)
        elif piece_type == 'knight':
            valid_moves = self._get_knight_moves(row, col, piece_color)
        elif piece_type == 'bishop':
            valid_moves = self._get_bishop_moves(row, col, piece_color)
        elif piece_type == 'queen':
            valid_moves = self._get_queen_moves(row, col, piece_color)
        elif piece_type == 'king':
            valid_moves = self._get_king_moves(row, col, piece_color)

        return valid_moves

    def _get_pawn_moves(self, row, col, color):
        """Get valid pawn moves"""
        moves = []
        direction = -1 if color == 'white' else 1
        start_row = 7 if color == 'white' else 1

        # Forward move
        new_row = row + direction
        if 0 <= new_row < 9 and not self.board[new_row][col]:
            moves.append((new_row, col))

            # Double move from starting position
            if row == start_row and not self.board[new_row + direction][col]:
                moves.append((new_row + direction, col))

        # Diagonal captures
        for dc in [-1, 1]:
            new_row, new_col = row + direction, col + dc
            if (0 <= new_row < 9 and 0 <= new_col < 9 and
                    self.board[new_row][new_col] and
                    self.board[new_row][new_col]['color'] != color):
                moves.append((new_row, new_col))

        return moves

    def _get_rook_moves(self, row, col, color):
        """Get valid rook moves (straight lines)"""
        moves = []
        directions = [(0, 1), (0, -1), (1, 0), (-1, 0)]

        for dr, dc in directions:
            for i in range(1, 9):
                new_row, new_col = row + dr * i, col + dc * i

                if not (0 <= new_row < 9 and 0 <= new_col < 9):
                    break

                target = self.board[new_row][new_col]
                if target:
                    if target['color'] != color:
                        moves.append((new_row, new_col))
                    break
                else:
                    moves.append((new_row, new_col))

        return moves

    def _get_knight_moves(self, row, col, color):
        """Get valid knight moves (L-shaped)"""
        moves = []
        knight_moves = [
            (-2, -1), (-2, 1), (-1, -2), (-1, 2),
            (1, -2), (1, 2), (2, -1), (2, 1)
        ]

        for dr, dc in knight_moves:
            new_row, new_col = row + dr, col + dc

            if 0 <= new_row < 9 and 0 <= new_col < 9:
                target = self.board[new_row][new_col]
                if not target or target['color'] != color:
                    moves.append((new_row, new_col))

        return moves

    def _get_bishop_moves(self, row, col, color):
        """Get valid bishop moves (diagonal lines)"""
        moves = []
        directions = [(1, 1), (1, -1), (-1, 1), (-1, -1)]

        for dr, dc in directions:
            for i in range(1, 9):
                new_row, new_col = row + dr * i, col + dc * i

                if not (0 <= new_row < 9 and 0 <= new_col < 9):
                    break

                target = self.board[new_row][new_col]
                if target:
                    if target['color'] != color:
                        moves.append((new_row, new_col))
                    break
                else:
                    moves.append((new_row, new_col))

        return moves

    def _get_queen_moves(self, row, col, color):
        """Get valid queen moves (combination of rook and bishop)"""
        moves = []
        moves.extend(self._get_rook_moves(row, col, color))
        moves.extend(self._get_bishop_moves(row, col, color))
        return moves

    def _get_king_moves(self, row, col, color):
        """Get valid king moves (one square in any direction)"""
        moves = []
        directions = [
            (-1, -1), (-1, 0), (-1, 1),
            (0, -1), (0, 1),
            (1, -1), (1, 0), (1, 1)
        ]

        for dr, dc in directions:
            new_row, new_col = row + dr, col + dc

            if 0 <= new_row < 9 and 0 <= new_col < 9:
                target = self.board[new_row][new_col]
                if not target or target['color'] != color:
                    moves.append((new_row, new_col))

        return moves

    def select_piece(self, row, col):
        """Select a piece if it belongs to the current player and it's their turn"""
        piece = self.board[row][col]

        if self.current_player != self.player_color:
            self.add_message("It's not your turn!")
            return

        if piece and piece['color'] == self.player_color:
            self.selected_piece = (row, col)
            self.valid_moves = self.get_valid_moves(row, col)
            if not self.valid_moves:
                self.add_message("This piece has no valid moves!")
        else:
            self.selected_piece = None
            self.valid_moves = []
            if piece and piece['color'] != self.player_color:
                self.add_message("❌ That's not your piece!")

    # Input handling
    def handle_click(self, pos):
        """Handle mouse clicks on the board"""
        if self.promotion_pending:
            self.handle_promotion_dialog_click(pos)
            return

        if self.state == GameState.PLAYING:
            board_x, board_y = pos
            if 0 <= board_x < BOARD_WIDTH and 0 <= board_y < BOARD_HEIGHT:
                col = board_x // CELL_SIZE
                row = board_y // CELL_SIZE

                if self.selected_piece:
                    from_row, from_col = self.selected_piece

                    if (row, col) == (from_row, from_col):
                        self.selected_piece = None
                        self.valid_moves = []
                        return

                    if (row, col) in self.valid_moves:
                        if self.needs_promotion(from_row, from_col, row, col):
                            self.promotion_pending = True
                            self.promotion_move = (from_row, from_col, row, col)
                            self.add_message("Choose promotion piece!")
                        else:
                            self.make_move(from_row, from_col, row, col)
                            self.add_message(
                                f"Move: {chr(ord('a') + from_col)}{9 - from_row} to {chr(ord('a') + col)}{9 - row}")
                    else:
                        self.select_piece(row, col)
                else:
                    self.select_piece(row, col)

    def handle_menu_click(self, pos):
        """Handle menu clicks with authentication check"""
        if self.connected and self.secure and self.authenticated:
            queue_button = pygame.Rect(WINDOW_WIDTH // 2 - 100, 200, 200, 50)
            if queue_button.collidepoint(pos):
                self.join_queue()

        if self.authenticated:
            logout_button = pygame.Rect(WINDOW_WIDTH // 2 - 75, 270, 150, 40)
            if logout_button.collidepoint(pos):
                self.logout()


    def handle_promotion_dialog_click(self, pos):
        """Handle clicks on the promotion dialog"""
        if not self.promotion_pending:
            return

        dialog_width = 400
        dialog_height = 200
        dialog_x = (WINDOW_WIDTH - dialog_width) // 2
        dialog_y = (WINDOW_HEIGHT - dialog_height) // 2

        option_size = 60
        spacing = 80
        start_x = dialog_x + (dialog_width - (len(self.promotion_options) * spacing - 20)) // 2
        option_y = dialog_y + 90

        click_x, click_y = pos

        for i, piece_type in enumerate(self.promotion_options):
            option_x = start_x + i * spacing

            if (option_x <= click_x <= option_x + option_size and
                    option_y <= click_y <= option_y + option_size):
                self.handle_promotion_choice(piece_type)
                return

    # Drawing methods
    def draw_login_screen(self):
        """Draw login screen"""
        self.screen.fill(WHITE)

        # Title
        title_text = self.title_font.render("Secure Chess Login", True, TEXT_COLOR)
        title_rect = title_text.get_rect(center=(WINDOW_WIDTH // 2, 100))
        self.screen.blit(title_text, title_rect)

        # Security info
        security_info = "End-to-End Encrypted Gaming"
        security_text = self.font.render(security_info, True, (0, 128, 0))
        security_rect = security_text.get_rect(center=(WINDOW_WIDTH // 2, 140))
        self.screen.blit(security_text, security_rect)

    def draw_register_screen(self):
        """Draw registration screen"""
        self.screen.fill(WHITE)

        # Title
        title_text = self.title_font.render("Create Account", True, TEXT_COLOR)
        title_rect = title_text.get_rect(center=(WINDOW_WIDTH // 2, 100))
        self.screen.blit(title_text, title_rect)

        # Instructions
        instruction_text = self.small_font.render("All fields are required", True, TEXT_COLOR)
        instruction_rect = instruction_text.get_rect(center=(WINDOW_WIDTH // 2, 140))
        self.screen.blit(instruction_text, instruction_rect)

    def draw_password_reset_screen(self):
        """Draw password reset screen"""
        self.screen.fill(WHITE)

        # Title
        title_text = self.title_font.render("Reset Password", True, TEXT_COLOR)
        title_rect = title_text.get_rect(center=(WINDOW_WIDTH // 2, 100))
        self.screen.blit(title_text, title_rect)

        # Instructions
        instruction_text = self.small_font.render("Enter email to receive reset code", True, TEXT_COLOR)
        instruction_rect = instruction_text.get_rect(center=(WINDOW_WIDTH // 2, 140))
        self.screen.blit(instruction_text, instruction_rect)

    def draw_board(self):
        # Draw coordinate labels
        coord_font = pygame.font.Font(None, 16)

        for col in range(BOARD_SIZE):
            x = col * CELL_SIZE + CELL_SIZE // 2
            label = chr(ord('a') + col)
            text = coord_font.render(label, True, TEXT_COLOR)
            text_rect = text.get_rect(center=(x, BOARD_HEIGHT + 10))
            self.screen.blit(text, text_rect)

        for row in range(BOARD_SIZE):
            y = row * CELL_SIZE + CELL_SIZE // 2
            label = str(9 - row)
            text = coord_font.render(label, True, TEXT_COLOR)
            text_rect = text.get_rect(center=(-15, y))
            self.screen.blit(text, text_rect)

        # Draw board squares
        for row in range(BOARD_SIZE):
            for col in range(BOARD_SIZE):
                x = col * CELL_SIZE
                y = row * CELL_SIZE

                # Checkerboard pattern
                color = LIGHT_BROWN if (row + col) % 2 == 0 else DARK_BROWN

                # Highlight king in check
                piece = self.board[row][col] if self.board and len(self.board) > row else None
                if (piece and piece['type'] == 'king' and piece['color'] == self.current_player
                        and self.in_check):
                    color = CHECK_COLOR

                pygame.draw.rect(self.screen, color, (x, y, CELL_SIZE, CELL_SIZE))

                # Highlight selected piece
                if self.selected_piece and self.selected_piece == (row, col):
                    highlight_surface = pygame.Surface((CELL_SIZE, CELL_SIZE), pygame.SRCALPHA)
                    highlight_surface.fill(SELECTED_COLOR)
                    self.screen.blit(highlight_surface, (x, y))

                # Highlight valid moves
                if (row, col) in self.valid_moves:
                    highlight_surface = pygame.Surface((CELL_SIZE, CELL_SIZE), pygame.SRCALPHA)
                    highlight_surface.fill(VALID_MOVE_COLOR)
                    self.screen.blit(highlight_surface, (x, y))

                    if not piece:
                        center = (x + CELL_SIZE // 2, y + CELL_SIZE // 2)
                        pygame.draw.circle(self.screen, (0, 200, 0), center, 8)
                    else:
                        pygame.draw.rect(self.screen, (200, 0, 0), (x, y, CELL_SIZE, CELL_SIZE), 4)

                # Draw piece
                if piece:
                    sprite = self.piece_sprites[piece['color']][piece['type']]
                    sprite_rect = sprite.get_rect(center=(x + CELL_SIZE // 2, y + CELL_SIZE // 2))
                    self.screen.blit(sprite, sprite_rect)

    def draw_sidebar(self):
        sidebar_x = BOARD_WIDTH
        sidebar_rect = pygame.Rect(sidebar_x, 0, SIDEBAR_WIDTH, WINDOW_HEIGHT)
        pygame.draw.rect(self.screen, WHITE, sidebar_rect)
        pygame.draw.line(self.screen, BLACK, (sidebar_x, 0), (sidebar_x, WINDOW_HEIGHT), 2)

        y_offset = 20

        # Title
        title_text = self.title_font.render("Secure Chess", True, TEXT_COLOR)
        self.screen.blit(title_text, (sidebar_x + 20, y_offset))
        y_offset += 60

        # Security status
        if self.secure:
            security_text = "Encrypted Connection"
            security_color = (0, 128, 0)
        else:
            security_text = "Unencrypted"
            security_color = (255, 0, 0)

        security_surface = self.small_font.render(security_text, True, security_color)
        self.screen.blit(security_surface, (sidebar_x + 20, y_offset))
        y_offset += 30

        # Game status
        if self.state == GameState.MENU:
            status_text = "Main Menu"
            status_color = TEXT_COLOR
        elif self.state == GameState.WAITING:
            status_text = "Waiting for opponent..."
            status_color = (255, 165, 0)
        elif self.state == GameState.PLAYING:
            if self.in_check:
                if self.current_player == self.player_color:
                    status_text = "YOU ARE IN CHECK!"
                    status_color = (255, 0, 0)
                else:
                    status_text = "Opponent in check"
                    status_color = (255, 165, 0)
            elif self.current_player == self.player_color:
                status_text = f"Your turn ({self.player_color})"
                status_color = (0, 128, 0)
            else:
                status_text = "Opponent's turn"
                status_color = (128, 0, 0)
        elif self.state == GameState.GAME_END:
            status_text = "Game Ended"
            status_color = TEXT_COLOR
        else:
            status_text = "Unknown State"
            status_color = TEXT_COLOR

        status_surface = self.font.render(status_text, True, status_color)
        self.screen.blit(status_surface, (sidebar_x + 20, y_offset))
        y_offset += 40

        # Player info
        if self.state == GameState.PLAYING:
            player_info = f"Playing as: {self.player_color.title()}"
            player_surface = self.small_font.render(player_info, True, TEXT_COLOR)
            self.screen.blit(player_surface, (sidebar_x + 20, y_offset))
            y_offset += 25

            turn_info = f"Current turn: {self.current_player.title()}"
            turn_color = (0, 128, 0) if self.current_player == self.player_color else (128, 0, 0)
            turn_surface = self.small_font.render(turn_info, True, turn_color)
            self.screen.blit(turn_surface, (sidebar_x + 20, y_offset))
            y_offset += 30

        # Connection status
        conn_status = "Connected" if self.connected else "Disconnected"
        conn_color = (0, 128, 0) if self.connected else (128, 0, 0)
        conn_text = self.font.render(f"Status: {conn_status}", True, conn_color)
        self.screen.blit(conn_text, (sidebar_x + 20, y_offset))
        y_offset += 40

        # Selected piece info
        if self.selected_piece and self.state == GameState.PLAYING:
            row, col = self.selected_piece
            piece = self.board[row][col]
            if piece:
                piece_info = f"Selected: {piece['type'].title()}"
                piece_surface = self.small_font.render(piece_info, True, (0, 0, 128))
                self.screen.blit(piece_surface, (sidebar_x + 20, y_offset))
                y_offset += 20

                moves_info = f"Valid moves: {len(self.valid_moves)}"
                moves_surface = self.small_font.render(moves_info, True, (0, 128, 0))
                self.screen.blit(moves_surface, (sidebar_x + 20, y_offset))
                y_offset += 30

        # Messages
        msg_title = self.font.render("Messages:", True, TEXT_COLOR)
        self.screen.blit(msg_title, (sidebar_x + 20, y_offset))
        y_offset += 30

        # Show last messages that fit
        remaining_height = WINDOW_HEIGHT - y_offset - 20
        lines_that_fit = remaining_height // 20
        start_idx = max(0, len(self.messages) - lines_that_fit)

        for i in range(start_idx, len(self.messages)):
            message = self.messages[i]
            if len(message) > 35:
                message = message[:32] + "..."

            msg_text = self.small_font.render(message, True, TEXT_COLOR)
            self.screen.blit(msg_text, (sidebar_x + 20, y_offset))
            y_offset += 20

    def draw_menu(self):
        self.screen.fill(WHITE)

        # Title with user info
        if self.username:
            title_text = f"Secure Chess - Welcome {self.username}!"
            title_font_size = min(48, max(24, 48 - len(self.username)))
            title_font = pygame.font.Font(None, title_font_size)
        else:
            title_text = "Secure Chess 9x9"
            title_font = self.title_font

        title_surface = title_font.render(title_text, True, TEXT_COLOR)
        title_rect = title_surface.get_rect(center=(WINDOW_WIDTH // 2, 100))
        self.screen.blit(title_surface, title_rect)

        # Security info
        security_info = "End-to-End Encrypted Gaming"
        security_text = self.font.render(security_info, True, (0, 128, 0))
        security_rect = security_text.get_rect(center=(WINDOW_WIDTH // 2, 140))
        self.screen.blit(security_text, security_rect)

        # Join queue button (only show if authenticated and connected)
        if self.connected and self.secure and self.authenticated:
            queue_button = pygame.Rect(WINDOW_WIDTH // 2 - 100, 200, 200, 50)
            pygame.draw.rect(self.screen, BUTTON_COLOR, queue_button)
            queue_text = self.font.render("Join Game Queue", True, WHITE)
            queue_text_rect = queue_text.get_rect(center=queue_button.center)
            self.screen.blit(queue_text, queue_text_rect)

        # Logout button
        if self.authenticated:
            logout_button = pygame.Rect(WINDOW_WIDTH // 2 - 75, 270, 150, 40)
            pygame.draw.rect(self.screen, (200, 100, 100), logout_button)
            logout_text = self.font.render("Logout", True, WHITE)
            logout_text_rect = logout_text.get_rect(center=logout_button.center)
            self.screen.blit(logout_text, logout_text_rect)

        # Instructions
        instructions = [
            "How to play:",
            "1. Join the game queue",
            "2. Wait for an opponent",
            "3. Click pieces to select and move",
            "4. Valid moves are highlighted in green",
            "5. Kings in check are highlighted in red",
            "",
            "Security Features:",
            "• User authentication system",
            "• Diffie-Hellman key exchange",
            "• AES-256-CBC encryption",
            "• Perfect forward secrecy",
            "• All game data encrypted"
        ]

        y_start = 330
        for i, instruction in enumerate(instructions):
            if instruction.startswith("•"):
                color = (0, 100, 0)
            elif instruction.startswith("🔒") or instruction.startswith("🎮"):
                color = (0, 0, 150)
            else:
                color = TEXT_COLOR

            instr_text = self.small_font.render(instruction, True, color)
            self.screen.blit(instr_text, (50, y_start + i * 25))

    def draw_waiting_screen(self):
        waiting_text = self.title_font.render("Waiting for opponent...", True, TEXT_COLOR)
        waiting_rect = waiting_text.get_rect(center=(BOARD_WIDTH // 2, BOARD_HEIGHT // 2))
        self.screen.blit(waiting_text, waiting_rect)

        # Security status
        if self.secure:
            secure_text = self.font.render("Secure connection established", True, (0, 128, 0))
            secure_rect = secure_text.get_rect(center=(BOARD_WIDTH // 2, BOARD_HEIGHT // 2 + 40))
            self.screen.blit(secure_text, secure_rect)

        # Animated dots
        dots = "." * ((pygame.time.get_ticks() // 500) % 4)
        dots_text = self.font.render(dots, True, TEXT_COLOR)
        dots_rect = dots_text.get_rect(center=(BOARD_WIDTH // 2, BOARD_HEIGHT // 2 + 80))
        self.screen.blit(dots_text, dots_rect)

    def draw_promotion_dialog(self):
        """Draw the pawn promotion dialog"""
        if not self.promotion_pending:
            return

        # Semi-transparent overlay
        overlay = pygame.Surface((WINDOW_WIDTH, WINDOW_HEIGHT), pygame.SRCALPHA)
        overlay.fill((0, 0, 0, 128))
        self.screen.blit(overlay, (0, 0))

        # Dialog box
        dialog_width = 400
        dialog_height = 200
        dialog_x = (WINDOW_WIDTH - dialog_width) // 2
        dialog_y = (WINDOW_HEIGHT - dialog_height) // 2

        pygame.draw.rect(self.screen, WHITE, (dialog_x, dialog_y, dialog_width, dialog_height))
        pygame.draw.rect(self.screen, BLACK, (dialog_x, dialog_y, dialog_width, dialog_height), 3)

        # Title
        title_text = self.font.render("Choose Promotion Piece", True, TEXT_COLOR)
        title_rect = title_text.get_rect(center=(dialog_x + dialog_width // 2, dialog_y + 30))
        self.screen.blit(title_text, title_rect)

        # Instructions
        instruction_text = self.small_font.render("Click piece or press Q/R/B/N", True, TEXT_COLOR)
        instruction_rect = instruction_text.get_rect(center=(dialog_x + dialog_width // 2, dialog_y + 50))
        self.screen.blit(instruction_text, instruction_rect)

        # Promotion options
        option_size = 60
        spacing = 80
        start_x = dialog_x + (dialog_width - (len(self.promotion_options) * spacing - 20)) // 2
        option_y = dialog_y + 90

        shortcuts = ['Q', 'R', 'B', 'N']

        for i, piece_type in enumerate(self.promotion_options):
            option_x = start_x + i * spacing

            # Draw piece sprite
            sprite = self.piece_sprites[self.player_color][piece_type]
            scaled_sprite = pygame.transform.scale(sprite, (option_size, option_size))
            sprite_rect = scaled_sprite.get_rect(center=(option_x + option_size // 2, option_y + option_size // 2))

            # Background for piece
            pygame.draw.rect(self.screen, LIGHT_BROWN, (option_x, option_y, option_size, option_size))
            pygame.draw.rect(self.screen, BLACK, (option_x, option_y, option_size, option_size), 2)

            self.screen.blit(scaled_sprite, sprite_rect)

            # Label with keyboard shortcut
            label_text = f"{piece_type.title()} ({shortcuts[i]})"
            label_surface = self.small_font.render(label_text, True, TEXT_COLOR)
            label_rect = label_surface.get_rect(center=(option_x + option_size // 2, option_y + option_size + 15))
            self.screen.blit(label_surface, label_rect)

    def draw_game_end_overlay(self):
        """Draw the game end overlay"""
        if not self.game_end_message:
            return

        # Check if timer has expired first
        current_time = pygame.time.get_ticks()
        if current_time >= self.game_end_timer:
            # Time's up, return to menu
            print("⏰ Game end timer expired, returning to menu")
            self.reset_to_menu()
            return

        # Semi-transparent overlay
        overlay = pygame.Surface((WINDOW_WIDTH, WINDOW_HEIGHT), pygame.SRCALPHA)
        overlay.fill((0, 0, 0, 180))
        self.screen.blit(overlay, (0, 0))

        # Main message box
        box_width = 500
        box_height = 300
        box_x = (WINDOW_WIDTH - box_width) // 2
        box_y = (WINDOW_HEIGHT - box_height) // 2

        pygame.draw.rect(self.screen, WHITE, (box_x, box_y, box_width, box_height))
        pygame.draw.rect(self.screen, BLACK, (box_x, box_y, box_width, box_height), 4)

        # Split message into lines
        lines = self.game_end_message.split('\n')

        # Draw each line
        y_start = box_y + 60
        for i, line in enumerate(lines):
            if i == 0:  # First line (result)
                text = self.large_font.render(line, True, TEXT_COLOR)
            else:
                text = self.font.render(line, True, TEXT_COLOR)

            text_rect = text.get_rect(center=(box_x + box_width // 2, y_start + i * 50))
            self.screen.blit(text, text_rect)

        # Countdown message
        remaining_time = max(0, (self.game_end_timer - current_time) / 1000)
        countdown_text = f"Returning to queue in {remaining_time:.1f}s..."
        countdown_surface = self.small_font.render(countdown_text, True, (128, 128, 128))
        countdown_rect = countdown_surface.get_rect(center=(box_x + box_width // 2, box_y + box_height - 60))
        self.screen.blit(countdown_surface, countdown_rect)

        # Click to continue hint
        hint_text = "Click anywhere or press any key to continue immediately"
        hint_surface = self.small_font.render(hint_text, True, (100, 100, 100))
        hint_rect = hint_surface.get_rect(center=(box_x + box_width // 2, box_y + box_height - 20))
        self.screen.blit(hint_surface, hint_rect)

    def draw_connection_screen(self):
        """Draw connection screen before login"""
        self.screen.fill(WHITE)

        # Title
        title_text = self.title_font.render("Secure Chess", True, TEXT_COLOR)
        title_rect = title_text.get_rect(center=(WINDOW_WIDTH // 2, 150))
        self.screen.blit(title_text, title_rect)

        # Connection status
        status_text = "🔗 Connecting to server..."
        status_surface = self.font.render(status_text, True, (255, 165, 0))
        status_rect = status_surface.get_rect(center=(WINDOW_WIDTH // 2, 250))
        self.screen.blit(status_surface, status_rect)

        # Auto-connect on first load
        if not hasattr(self, '_connection_attempted'):
            self._connection_attempted = True
            if self.connect_to_server():
                # Connection successful, stay on login screen
                pass
            else:
                # Show retry option
                retry_text = "❌ Connection failed. Click to retry"
                retry_surface = self.font.render(retry_text, True, (255, 0, 0))
                retry_rect = retry_surface.get_rect(center=(WINDOW_WIDTH // 2, 300))
                self.screen.blit(retry_surface, retry_rect)

    def logout(self):
        """Logout user and return to login screen"""
        self.authenticated = False
        self.username = None
        self.state = GameState.LOGIN
        self.setup_login_ui()
        self.add_message("👋 Logged out successfully")

    def reset_to_login(self):
        """Reset to login state"""
        self.state = GameState.LOGIN
        self.authenticated = False
        self.username = None
        self.setup_login_ui()

    def reset_to_menu(self):
        """Reset all game state and return to menu"""
        print("🔄 Resetting to menu state")
        if self.authenticated:
            self.state = GameState.MENU
            self.clear_ui()  # Clear any auth UI elements
        else:
            self.state = GameState.LOGIN
            self.setup_login_ui()

        self.game_end_message = ""
        self.game_end_timer = 0
        self.in_check = False
        self.selected_piece = None
        self.valid_moves = []
        self.board = [[None for _ in range(9)] for _ in range(9)]
        self.player_color = None
        self.game_id = None
        self.current_player = "white"
        self.promotion_pending = False
        self.promotion_move = None

    def check_for_stuck_state(self, current_time):
        """Check if the client is stuck and needs to be reset"""
        # If in playing state but no moves for 30 seconds, something might be wrong
        if (self.state == GameState.PLAYING and
                self.last_move_time > 0 and
                current_time - self.last_move_time > 30000):  # 30 seconds

            print("⚠️ WARNING: No moves for 30 seconds, checking connection...")
            if not self.connected:
                print("📡 Connection lost, returning to menu")
                self.reset_to_menu()

        # If game has been in an unusual state for too long, reset
        if (self.state not in [GameState.MENU, GameState.WAITING, GameState.PLAYING, GameState.GAME_END]):
            print(f"⚠️ WARNING: Invalid state {self.state}, resetting to menu")
            self.reset_to_menu()

    # Main game loop
    def run(self):
        print("🎮 Starting Secure Chess Client...")

        while self.running:
            time_delta = self.clock.tick(60) / 1000.0
            current_time = pygame.time.get_ticks()

            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    self.running = False

                # Handle GUI events for authentication screens
                if self.state in [GameState.LOGIN, GameState.REGISTER, GameState.PASSWORD_RESET]:
                    self.handle_ui_event(event)
                    self.gui_manager.process_events(event)

                    # Handle keyboard shortcuts for login
                    if event.type == pygame.KEYDOWN:
                        if event.key == pygame.K_RETURN and self.state == GameState.LOGIN:
                            self.attempt_login()
                        elif event.key == pygame.K_ESCAPE:
                            if self.state != GameState.LOGIN:
                                self.state = GameState.LOGIN
                                self.setup_login_ui()

                elif event.type == pygame.MOUSEBUTTONDOWN:
                    if event.button == 1:  # Left click
                        if self.state == GameState.MENU:
                            self.handle_menu_click(event.pos)
                        elif self.state == GameState.PLAYING:
                            self.handle_click(event.pos)
                        elif self.state == GameState.GAME_END:
                            print("👆 Game end screen clicked, returning to menu")
                            self.reset_to_menu()

                elif event.type == pygame.KEYDOWN:
                    if self.promotion_pending:
                        # Handle promotion keyboard shortcuts
                        if event.key == pygame.K_q:
                            self.handle_promotion_choice('queen')
                        elif event.key == pygame.K_r:
                            self.handle_promotion_choice('rook')
                        elif event.key == pygame.K_b:
                            self.handle_promotion_choice('bishop')
                        elif event.key == pygame.K_n:
                            self.handle_promotion_choice('knight')
                        elif event.key == pygame.K_ESCAPE:
                            self.handle_promotion_choice('queen')
                    elif self.state == GameState.GAME_END:
                        print("⌨️ Key pressed in game end, returning to menu")
                        self.reset_to_menu()
                    else:
                        if event.key == pygame.K_ESCAPE:
                            if self.state == GameState.PLAYING:
                                # Don't allow escape from game
                                pass
                            elif self.state == GameState.WAITING:
                                self.state = GameState.MENU
                            elif self.state == GameState.MENU and self.authenticated:
                                # Logout option
                                self.logout()

            # Update GUI manager
            if self.state in [GameState.LOGIN, GameState.REGISTER, GameState.PASSWORD_RESET]:
                self.gui_manager.update(time_delta)

            # Clear screen
            self.screen.fill(WHITE)

            # Draw based on current state
            if self.state == GameState.LOGIN:
                if not self.connected:
                    # Show connection screen first
                    self.draw_connection_screen()
                else:
                    self.draw_login_screen()
            elif self.state == GameState.REGISTER:
                self.draw_register_screen()
            elif self.state == GameState.PASSWORD_RESET:
                self.draw_password_reset_screen()
            elif self.state == GameState.MENU:
                self.draw_menu()
            elif self.state == GameState.WAITING:
                self.draw_waiting_screen()
                self.draw_sidebar()
            elif self.state == GameState.PLAYING:
                if not self.connected or not self.game_id:
                    print("⚠️ Safety check: Not connected or no game_id, returning to menu")
                    self.reset_to_menu()
                else:
                    self.draw_board()
                    self.draw_sidebar()
            elif self.state == GameState.GAME_END:
                self.draw_board()
                self.draw_sidebar()
                self.draw_game_end_overlay()
            else:
                print(f"❓ Unknown state: {self.state}, resetting to login")
                self.reset_to_login()

            # Draw GUI elements
            if self.state in [GameState.LOGIN, GameState.REGISTER, GameState.PASSWORD_RESET]:
                self.gui_manager.draw_ui(self.screen)

            # Draw promotion dialog on top if needed
            if self.promotion_pending:
                self.draw_promotion_dialog()

            pygame.display.flip()

        # Cleanup
        print("🧹 Cleaning up client...")
        if self.connected:
            try:
                self.socket.close()
            except:
                pass
        pygame.quit()



def check_pygame_gui():
    """Check and install pygame_gui if needed"""
    try:
        import pygame_gui
        return True
    except ImportError:
        print("📦 Installing pygame_gui...")
        import subprocess
        import sys
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pygame_gui"])
            print("✅ pygame_gui installed successfully!")
            return True
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install pygame_gui: {e}")
            return False


def main():
    """Main client function with enhanced error handling"""
    # Check required dependencies
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
        print("✅ Cryptography library found")
    except ImportError:
        print("📦 Installing required cryptography library...")
        import subprocess
        import sys
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
            print("✅ Cryptography library installed successfully!")
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to install cryptography library: {e}")
            print("Please install manually: pip install cryptography")
            return

    # Check pygame_gui
    if not check_pygame_gui():
        print("❌ pygame_gui is required for the login system")
        print("Please install manually: pip install pygame_gui")
        return

    # Create and run client
    client = SecureChessClient()
    try:
        client.run()
    except KeyboardInterrupt:
        print("\n🛑 Client shutting down...")
    except Exception as e:
        print(f"❌ Client error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if hasattr(client, 'connected') and client.connected:
            try:
                client.socket.close()
            except:
                pass
        try:
            pygame.quit()
        except:
            pass
    print("✅ Client shutdown complete")


if __name__ == "__main__":
    main()
