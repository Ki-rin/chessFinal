import pickle
import socket
import threading
import json
import time
import os
import hashlib
import secrets
from enum import Enum
import pickle
import hashlib
import secrets
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


class UserDatabase:
    def __init__(self, db_file='users.db'):
        self.db_file = db_file
        self.pepper = "SECURE_CHESS_PEPPER_2025"  # Change this in production
        self.users = self.load_database()
        self.password_reset_codes = {}  # email -> (code, expiry_time)

    def load_database(self):
        """Load user database from pickle file"""
        try:
            with open(self.db_file, 'rb') as f:
                return pickle.load(f)
        except FileNotFoundError:
            print("📁 Creating new user database...")
            return {}
        except Exception as e:
            print(f"❌ Error loading database: {e}")
            return {}

    def save_database(self):
        """Save user database to pickle file"""
        try:
            with open(self.db_file, 'wb') as f:
                pickle.dump(self.users, f)
            return True
        except Exception as e:
            print(f"❌ Error saving database: {e}")
            return False

    def hash_password(self, password, salt):
        """Hash password with salt and pepper"""
        salted_peppered = password + salt + self.pepper
        return hashlib.sha256(salted_peppered.encode()).hexdigest()

    def register_user(self, username, password, email):
        """Register a new user"""
        if username in self.users:
            return {"success": False, "message": "Username already exists"}

        if any(user['email'] == email for user in self.users.values()):
            return {"success": False, "message": "Email already registered"}

        # Generate salt and hash password
        salt = secrets.token_hex(16)
        password_hash = self.hash_password(password, salt)

        # Store user data
        self.users[username] = {
            'password_hash': password_hash,
            'salt': salt,
            'email': email,
            'created_at': datetime.now().isoformat(),
            'last_login': None
        }

        if self.save_database():
            print(f"👤 New user registered: {username}")
            return {"success": True, "message": "User registered successfully"}
        else:
            return {"success": False, "message": "Database error"}

    def authenticate_user(self, username, password):
        """Authenticate user login"""
        if username not in self.users:
            return {"success": False, "message": "Invalid username or password"}

        user_data = self.users[username]
        password_hash = self.hash_password(password, user_data['salt'])

        if password_hash == user_data['password_hash']:
            # Update last login
            self.users[username]['last_login'] = datetime.now().isoformat()
            self.save_database()
            print(f"🔐 User authenticated: {username}")
            return {"success": True, "message": "Login successful", "user": username}
        else:
            return {"success": False, "message": "Invalid username or password"}

    def send_reset_code(self, email, smtp_config=None):
        """Send password reset code via email"""
        # Find user by email
        username = None
        for user, data in self.users.items():
            if data['email'] == email:
                username = user
                break

        if not username:
            return {"success": False, "message": "Email not found"}

        # Generate 6-digit code
        reset_code = str(random.randint(100000, 999999))
        expiry_time = datetime.now() + timedelta(minutes=15)  # 15 minute expiry

        self.password_reset_codes[email] = (reset_code, expiry_time)

        # Send email (configure SMTP settings as needed)
        if smtp_config:
            try:
                msg = MIMEMultipart()
                msg['From'] = smtp_config['from_email']
                msg['To'] = email
                msg['Subject'] = "Secure Chess - Password Reset Code"

                body = f"""
                Your password reset code is: {reset_code}

                This code will expire in 15 minutes.
                If you didn't request this reset, please ignore this email.

                - Secure Chess Team
                """

                msg.attach(MIMEText(body, 'plain'))

                server = smtplib.SMTP(smtp_config['smtp_server'], smtp_config['smtp_port'])
                server.starttls()
                server.login(smtp_config['from_email'], smtp_config['password'])
                server.send_message(msg)
                server.quit()

                print(f"📧 Reset code sent to {email}")
                return {"success": True, "message": "Reset code sent to email"}
            except Exception as e:
                print(f"❌ Email send error: {e}")
                # For demo purposes, print the code
                print(f"🔑 Demo mode - Reset code for {email}: {reset_code}")
                return {"success": True, "message": f"Demo: Reset code is {reset_code}"}
        else:
            # Demo mode - just print the code
            print(f"🔑 Demo mode - Reset code for {email}: {reset_code}")
            return {"success": True, "message": f"Demo: Reset code is {reset_code}"}

    def verify_reset_code(self, email, code):
        """Verify password reset code"""
        if email not in self.password_reset_codes:
            return {"success": False, "message": "No reset code found"}

        stored_code, expiry_time = self.password_reset_codes[email]

        if datetime.now() > expiry_time:
            del self.password_reset_codes[email]
            return {"success": False, "message": "Reset code expired"}

        if code != stored_code:
            return {"success": False, "message": "Invalid reset code"}

        return {"success": True, "message": "Code verified"}

    def reset_password(self, email, code, new_password):
        """Reset password with verified code"""
        # Verify code first
        verify_result = self.verify_reset_code(email, code)
        if not verify_result["success"]:
            return verify_result

        # Find username by email
        username = None
        for user, data in self.users.items():
            if data['email'] == email:
                username = user
                break

        if not username:
            return {"success": False, "message": "User not found"}

        # Generate new salt and hash
        salt = secrets.token_hex(16)
        password_hash = self.hash_password(new_password, salt)

        # Update password
        self.users[username]['password_hash'] = password_hash
        self.users[username]['salt'] = salt

        # Remove used reset code
        del self.password_reset_codes[email]

        if self.save_database():
            print(f"🔑 Password reset for user: {username}")
            return {"success": True, "message": "Password reset successfully"}
        else:
            return {"success": False, "message": "Database error"}


def backup_database():
    """Create a backup of the user database"""
    import shutil
    import datetime

    if os.path.exists('users.db'):
        backup_name = f"users_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        shutil.copy2('users.db', backup_name)
        print(f"💾 Database backed up to {backup_name}")
        return True
    return False


def reset_database():
    """Reset the user database (admin function)"""
    import os
    if os.path.exists('users.db'):
        os.remove('users.db')
        print("🗑️ User database reset")
        return True
    return False


def list_users():
    """List all registered users (admin function)"""
    try:
        with open('users.db', 'rb') as f:
            users = pickle.load(f)

        print(f"👥 Registered Users ({len(users)}):")
        for username, data in users.items():
            last_login = data.get('last_login', 'Never')
            if last_login and last_login != 'Never':
                last_login = last_login[:19]  # Show date/time only
            print(f"  • {username} ({data['email']}) - Last login: {last_login}")

        return users
    except FileNotFoundError:
        print("📁 No user database found")
        return {}
    except Exception as e:
        print(f"❌ Error reading database: {e}")
        return {}

def load_email_config():
    """Load email configuration from config.py"""
    try:
        from config import EMAIL_CONFIG
        if EMAIL_CONFIG.get('enabled', False):
            return EMAIL_CONFIG
        else:
            print("📧 Email functionality disabled in config.py")
            return None
    except ImportError:
        print("📧 No config.py found - email functionality disabled")
        print("💡 Create config.py to enable password reset emails")
        return None
    except Exception as e:
        print(f"❌ Error loading email config: {e}")
        return None


class PieceType(Enum):
    PAWN = "pawn"
    ROOK = "rook"
    KNIGHT = "knight"
    BISHOP = "bishop"
    QUEEN = "queen"
    KING = "king"


class PieceColor(Enum):
    WHITE = "white"
    BLACK = "black"


class GameState(Enum):
    WAITING = "waiting"
    PLAYING = "playing"
    FINISHED = "finished"


class CryptoManager:
    """Handles Diffie-Hellman key exchange and AES encryption/decryption"""

    # Standard DH parameters (RFC 3526 - 2048-bit MODP Group)
    DH_PRIME = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    DH_GENERATOR = 2

    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        self.aes_key = None

    def generate_dh_keypair(self):
        """Generate DH private and public keys"""
        self.private_key = secrets.randbelow(self.DH_PRIME - 2) + 1
        self.public_key = pow(self.DH_GENERATOR, self.private_key, self.DH_PRIME)
        return self.public_key

    def compute_shared_secret(self, other_public_key):
        """Compute shared secret from other party's public key"""
        if self.private_key is None:
            raise ValueError("Must generate keypair first")

        self.shared_secret = pow(other_public_key, self.private_key, self.DH_PRIME)

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


class ChessPiece:
    def __init__(self, piece_type, color, row, col):
        self.type = piece_type
        self.color = color
        self.row = row
        self.col = col
        self.has_moved = False

    def to_dict(self):
        return {
            'type': self.type.value,
            'color': self.color.value,
            'row': self.row,
            'col': self.col,
            'has_moved': self.has_moved
        }


class ChessGame:
    def __init__(self, game_id):
        self.game_id = game_id
        self.board = [[None for _ in range(9)] for _ in range(9)]
        self.current_player = PieceColor.WHITE
        self.state = GameState.WAITING
        self.players = {}
        self.spectators = []
        self.setup_board()

    def setup_board(self):
        # Setup white pieces (bottom)
        piece_order = [PieceType.ROOK, PieceType.KNIGHT, PieceType.BISHOP, PieceType.QUEEN,
                       PieceType.KING, PieceType.QUEEN, PieceType.BISHOP, PieceType.KNIGHT, PieceType.ROOK]

        for col in range(9):
            self.board[8][col] = ChessPiece(piece_order[col], PieceColor.WHITE, 8, col)
            self.board[7][col] = ChessPiece(PieceType.PAWN, PieceColor.WHITE, 7, col)

        # Setup black pieces (top)
        for col in range(9):
            self.board[0][col] = ChessPiece(piece_order[col], PieceColor.BLACK, 0, col)
            self.board[1][col] = ChessPiece(PieceType.PAWN, PieceColor.BLACK, 1, col)

    def is_valid_move(self, from_row, from_col, to_row, to_col, player_color):
        # Basic bounds checking
        if not (0 <= from_row < 9 and 0 <= from_col < 9 and 0 <= to_row < 9 and 0 <= to_col < 9):
            return False

        piece = self.board[from_row][from_col]
        if not piece or piece.color != player_color:
            return False

        # Can't capture own pieces
        target = self.board[to_row][to_col]
        if target and target.color == player_color:
            return False

        # Piece-specific movement validation
        if not self._validate_piece_movement(piece, from_row, from_col, to_row, to_col):
            return False

        # Check if this move would leave the king in check
        return self.is_move_legal(from_row, from_col, to_row, to_col, player_color)

    def make_move(self, from_row, from_col, to_row, to_col, player_color, promotion_piece=None):
        if not self.is_valid_move(from_row, from_col, to_row, to_col, player_color):
            return False

        piece = self.board[from_row][from_col]
        captured_piece = self.board[to_row][to_col]

        # Move the piece
        self.board[to_row][to_col] = piece
        self.board[from_row][from_col] = None

        piece.row = to_row
        piece.col = to_col
        piece.has_moved = True

        # Check for pawn promotion
        promotion_occurred = False
        if piece.type == PieceType.PAWN:
            promotion_row = 0 if piece.color == PieceColor.WHITE else 8
            if to_row == promotion_row:
                # Promote pawn
                if promotion_piece and promotion_piece in ['queen', 'rook', 'bishop', 'knight']:
                    piece.type = PieceType(promotion_piece)
                    promotion_occurred = True
                else:
                    # Default to queen if no promotion piece specified
                    piece.type = PieceType.QUEEN
                    promotion_occurred = True

        # Switch turns BEFORE checking game status
        self.current_player = PieceColor.BLACK if self.current_player == PieceColor.WHITE else PieceColor.WHITE

        # Check game status after switching turns
        game_status = self.get_game_status()

        return {
            'success': True,
            'promotion': promotion_occurred,
            'promoted_to': piece.type.value if promotion_occurred else None,
            'captured': captured_piece.to_dict() if captured_piece else None,
            'game_status': game_status
        }

    def _validate_piece_movement(self, piece, from_row, from_col, to_row, to_col):
        row_diff = abs(to_row - from_row)
        col_diff = abs(to_col - from_col)

        if piece.type == PieceType.PAWN:
            return self._validate_pawn_move(piece, from_row, from_col, to_row, to_col)
        elif piece.type == PieceType.ROOK:
            return self._validate_rook_move(from_row, from_col, to_row, to_col)
        elif piece.type == PieceType.KNIGHT:
            return (row_diff == 2 and col_diff == 1) or (row_diff == 1 and col_diff == 2)
        elif piece.type == PieceType.BISHOP:
            return self._validate_bishop_move(from_row, from_col, to_row, to_col)
        elif piece.type == PieceType.QUEEN:
            return (self._validate_rook_move(from_row, from_col, to_row, to_col) or
                    self._validate_bishop_move(from_row, from_col, to_row, to_col))
        elif piece.type == PieceType.KING:
            return row_diff <= 1 and col_diff <= 1 and (row_diff + col_diff > 0)

        return False

    def _validate_pawn_move(self, piece, from_row, from_col, to_row, to_col):
        direction = -1 if piece.color == PieceColor.WHITE else 1
        row_diff = to_row - from_row
        col_diff = abs(to_col - from_col)

        # Forward move (no capture)
        if col_diff == 0:
            if row_diff == direction and not self.board[to_row][to_col]:
                return True
            # Double move from starting position
            if (not piece.has_moved and row_diff == 2 * direction and
                    not self.board[to_row][to_col] and not self.board[from_row + direction][from_col]):
                return True
        # Diagonal capture
        elif col_diff == 1 and row_diff == direction:
            # For regular move validation, there must be an enemy piece to capture
            target_piece = self.board[to_row][to_col]
            if target_piece and target_piece.color != piece.color:
                return True

        return False

    def _validate_rook_move(self, from_row, from_col, to_row, to_col):
        if from_row != to_row and from_col != to_col:
            return False
        return self._is_path_clear(from_row, from_col, to_row, to_col)

    def _validate_bishop_move(self, from_row, from_col, to_row, to_col):
        if abs(to_row - from_row) != abs(to_col - from_col):
            return False
        return self._is_path_clear(from_row, from_col, to_row, to_col)

    def _is_path_clear(self, from_row, from_col, to_row, to_col):
        row_step = 0 if from_row == to_row else (1 if to_row > from_row else -1)
        col_step = 0 if from_col == to_col else (1 if to_col > from_col else -1)

        current_row, current_col = from_row + row_step, from_col + col_step

        while current_row != to_row or current_col != to_col:
            if self.board[current_row][current_col]:
                return False
            current_row += row_step
            current_col += col_step

        return True

    def find_king(self, color):
        """Find the king of the specified color"""
        for row in range(9):
            for col in range(9):
                piece = self.board[row][col]
                if piece and piece.type == PieceType.KING and piece.color == color:
                    return (row, col)
        return None

    def is_square_attacked(self, row, col, attacking_color):
        """Check if a square is attacked by any piece of the attacking color"""
        for r in range(9):
            for c in range(9):
                piece = self.board[r][c]
                if piece and piece.color == attacking_color:
                    if self._can_piece_attack_square(piece, r, c, row, col):
                        return True
        return False

    def _can_piece_attack_square(self, piece, from_row, from_col, target_row, target_col):
        """Check if a piece can attack a specific square"""
        # Special handling for pawns since they attack differently than they move
        if piece.type == PieceType.PAWN:
            return self._can_pawn_attack_square(piece, from_row, from_col, target_row, target_col)

        # For other pieces, temporarily remove the target piece to check if it can be attacked
        original_piece = self.board[target_row][target_col]
        self.board[target_row][target_col] = None

        can_attack = self._validate_piece_movement(piece, from_row, from_col, target_row, target_col)

        # Restore the original piece
        self.board[target_row][target_col] = original_piece

        return can_attack

    def _can_pawn_attack_square(self, pawn, from_row, from_col, target_row, target_col):
        """Check if a pawn can attack a specific square"""
        direction = -1 if pawn.color == PieceColor.WHITE else 1

        # Pawn attacks diagonally one square forward
        if target_row == from_row + direction:
            if abs(target_col - from_col) == 1:
                return True

        return False

    def is_in_check(self, color):
        """Check if the king of the specified color is in check"""
        king_pos = self.find_king(color)
        if not king_pos:
            print(f"Warning: No king found for {color.value}")
            return False

        enemy_color = PieceColor.BLACK if color == PieceColor.WHITE else PieceColor.WHITE
        king_row, king_col = king_pos

        # Check if any enemy piece can attack the king
        for row in range(9):
            for col in range(9):
                piece = self.board[row][col]
                if piece and piece.color == enemy_color:
                    if self._can_piece_attack_square(piece, row, col, king_row, king_col):
                        print(
                            f"{color.value} king at ({king_row}, {king_col}) is in check from {piece.type.value} at ({row}, {col})")
                        return True

        return False

    def is_move_legal(self, from_row, from_col, to_row, to_col, color):
        """Check if a move is legal (doesn't leave king in check)"""
        # Make the move temporarily
        piece = self.board[from_row][from_col]
        captured = self.board[to_row][to_col]

        self.board[to_row][to_col] = piece
        self.board[from_row][from_col] = None

        # Check if king is in check after this move
        king_safe = not self.is_in_check(color)

        # Restore the board
        self.board[from_row][from_col] = piece
        self.board[to_row][to_col] = captured

        return king_safe

    def get_legal_moves(self, color):
        """Get all legal moves (that don't leave king in check)"""
        legal_moves = []

        for row in range(9):
            for col in range(9):
                piece = self.board[row][col]
                if piece and piece.color == color:
                    # Get all possible moves for this piece
                    for target_row in range(9):
                        for target_col in range(9):
                            if self.is_valid_move(row, col, target_row, target_col, color):
                                # Make the move temporarily to see if it leaves king in check
                                original_piece = self.board[target_row][target_col]
                                self.board[target_row][target_col] = piece
                                self.board[row][col] = None

                                # Check if king is safe after this move
                                king_safe = not self.is_in_check(color)

                                # Restore the board
                                self.board[row][col] = piece
                                self.board[target_row][target_col] = original_piece

                                if king_safe:
                                    legal_moves.append((row, col, target_row, target_col))

        print(f"{color.value} has {len(legal_moves)} legal moves")
        return legal_moves

    def is_checkmate(self, color):
        """Check if the specified color is in checkmate"""
        if not self.is_in_check(color):
            return False

        # If in check, see if there are any legal moves
        legal_moves = self.get_legal_moves(color)
        return len(legal_moves) == 0

    def is_stalemate(self, color):
        """Check if the specified color is in stalemate"""
        if self.is_in_check(color):
            return False

        # If not in check, see if there are any legal moves
        legal_moves = self.get_legal_moves(color)
        return len(legal_moves) == 0

    def get_game_status(self):
        """Get the current game status"""
        current_color = self.current_player

        if self.is_checkmate(current_color):
            winner = PieceColor.BLACK if current_color == PieceColor.WHITE else PieceColor.WHITE
            loser = current_color
            return {
                'status': 'checkmate',
                'winner': winner.value,
                'loser': loser.value,
                'message': f'Checkmate! {winner.value.title()} wins!',
                'in_checkmate': loser.value
            }
        elif self.is_stalemate(current_color):
            return {
                'status': 'stalemate',
                'message': 'Stalemate! Game is a draw.'
            }
        elif self.is_in_check(current_color):
            return {
                'status': 'check',
                'in_check': current_color.value,
                'message': f'{current_color.value.title()} is in check!'
            }
        else:
            return {
                'status': 'playing',
                'message': 'Game continues.'
            }

    def get_board_state(self):
        board_data = []
        for row in self.board:
            row_data = []
            for piece in row:
                row_data.append(piece.to_dict() if piece else None)
            board_data.append(row_data)
        return board_data


class SecureChessServer:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}
        self.games = {}
        self.waiting_players = []
        self.game_counter = 0
        # Initialize user database and email config
        self.user_db = UserDatabase()
        self.smtp_config = load_email_config()
        self.rate_limiter = RateLimiter()

        if self.smtp_config:
            print("✅ Email configuration loaded - password reset emails enabled")
            print(f"📧 SMTP Server: {self.smtp_config['smtp_server']}")
        else:
            print("⚠️ Email configuration not available - password reset will show codes in console")


    def log_security_event(self, event_type, client_id, details=None):
        """Log security-related events"""
        timestamp = datetime.now().isoformat()
        client_info = self.clients.get(client_id, {})
        username = client_info.get('username', 'unknown')
        address = client_info.get('address', 'unknown')

        log_entry = f"[{timestamp}] {event_type} - User: {username}, Client: {client_id}, IP: {address}"
        if details:
            log_entry += f", Details: {details}"

        print(f"🔐 {log_entry}")

        # Optionally save to security log file
        try:
            with open('security.log', 'a') as f:
                f.write(log_entry + '\n')
        except:
            pass


    # Enhanced authentication handlers with logging
    def handle_login(self, client_id, message):
        """"Handle user login with rate limiting and enhanced security logging"""
        client = self.clients[client_id]
        ip_address = str(client['address'][0])

        # Check rate limiting
        if self.rate_limiter.is_rate_limited(ip_address, 'login'):
            self.log_security_event("LOGIN_RATE_LIMITED", client_id, f"IP: {ip_address}")
            self.send_error(client_id, "Too many login attempts. Please try again later.")
            return

        username = message.get('username', '').strip()
        password = message.get('password', '')

        # Record the attempt
        self.rate_limiter.record_attempt(ip_address, 'login')

        if not username or not password:
            self.log_security_event("LOGIN_FAILED", client_id, "Missing credentials")
            self.send_error(client_id, "Username and password required")
            return

        result = self.user_db.authenticate_user(username, password)

        if result["success"]:
            self.clients[client_id]['authenticated'] = True
            self.clients[client_id]['username'] = username

            self.log_security_event("LOGIN_SUCCESS", client_id, f"User {username}")

            self.send_encrypted_message(client_id, {
                'type': 'login_success',
                'message': result["message"],
                'username': username
            })
        else:
            self.log_security_event("LOGIN_FAILED", client_id, f"Invalid credentials for {username}")
            self.send_error(client_id, result["message"])

    def handle_register(self, client_id, message):
        """Handle user registration with rate limiting and enhanced validation"""
        client = self.clients[client_id]
        ip_address = str(client['address'][0])

        # Check rate limiting
        if self.rate_limiter.is_rate_limited(ip_address, 'register'):
            self.log_security_event("REGISTER_RATE_LIMITED", client_id, f"IP: {ip_address}")
            self.send_error(client_id, "Too many registration attempts. Please try again later.")
            return

        username = message.get('username', '').strip()
        password = message.get('password', '')
        email = message.get('email', '').strip()

        # Record the attempt
        self.rate_limiter.record_attempt(ip_address, 'register')

        # Enhanced validation
        if not username or not password or not email:
            self.log_security_event("REGISTER_FAILED", client_id, "Missing required fields")
            self.send_error(client_id, "All fields are required")
            return

        if len(username) < 3 or len(username) > 20:
            self.log_security_event("REGISTER_FAILED", client_id, f"Invalid username length: {username}")
            self.send_error(client_id, "Username must be 3-20 characters")
            return

        if len(password) < 6 or len(password) > 100:
            self.log_security_event("REGISTER_FAILED", client_id, "Invalid password length")
            self.send_error(client_id, "Password must be 6-100 characters")
            return

        if '@' not in email or '.' not in email or len(email) > 100:
            self.log_security_event("REGISTER_FAILED", client_id, f"Invalid email: {email}")
            self.send_error(client_id, "Invalid email format")
            return

        # Check for username/email restrictions
        prohibited_usernames = ['admin', 'root', 'system', 'server', 'bot', 'moderator', 'guest']
        if username.lower() in prohibited_usernames:
            self.log_security_event("REGISTER_FAILED", client_id, f"Prohibited username: {username}")
            self.send_error(client_id, "Username not allowed")
            return

        # Check for alphanumeric username
        if not username.replace('_', '').replace('-', '').isalnum():
            self.log_security_event("REGISTER_FAILED", client_id, f"Invalid username characters: {username}")
            self.send_error(client_id, "Username can only contain letters, numbers, hyphens, and underscores")
            return

        result = self.user_db.register_user(username, password, email)

        if result["success"]:
            self.log_security_event("REGISTER_SUCCESS", client_id, f"New user: {username} ({email})")
            self.send_encrypted_message(client_id, {
                'type': 'register_success',
                'message': result["message"]
            })
        else:
            self.log_security_event("REGISTER_FAILED", client_id,
                                    f"Registration failed for {username}: {result['message']}")
            self.send_error(client_id, result["message"])

    def handle_password_reset_request(self, client_id, message):
        """Handle password reset request with rate limiting"""
        client = self.clients[client_id]
        ip_address = str(client['address'][0])

        # Check rate limiting
        if self.rate_limiter.is_rate_limited(ip_address, 'reset'):
            self.log_security_event("RESET_RATE_LIMITED", client_id, f"IP: {ip_address}")
            self.send_error(client_id, "Too many reset attempts. Please try again later.")
            return

        email = message.get('email', '').strip()

        # Record the attempt
        self.rate_limiter.record_attempt(ip_address, 'reset')

        if not email:
            self.log_security_event("RESET_REQUEST_FAILED", client_id, "No email provided")
            self.send_error(client_id, "Email required")
            return

        if len(email) > 100:
            self.log_security_event("RESET_REQUEST_FAILED", client_id, f"Email too long: {email}")
            self.send_error(client_id, "Invalid email")
            return

        self.log_security_event("RESET_REQUEST", client_id, f"Password reset requested for {email}")

        result = self.user_db.send_reset_code(email, self.smtp_config)

        self.send_encrypted_message(client_id, {
            'type': 'reset_code_sent',
            'message': result["message"],
            'success': result["success"]
        })

    def handle_password_reset(self, client_id, message):
        """Handle password reset with enhanced logging"""
        email = message.get('email', '').strip()
        code = message.get('code', '').strip()
        new_password = message.get('new_password', '')

        if not email or not code or not new_password:
            self.log_security_event("PASSWORD_RESET_FAILED", client_id, "Missing required fields")
            self.send_error(client_id, "All fields required")
            return

        if len(new_password) < 6:
            self.log_security_event("PASSWORD_RESET_FAILED", client_id, "New password too short")
            self.send_error(client_id, "Password must be at least 6 characters")
            return

        result = self.user_db.reset_password(email, code, new_password)

        if result["success"]:
            self.log_security_event("PASSWORD_RESET_SUCCESS", client_id, f"Password reset for {email}")
        else:
            self.log_security_event("PASSWORD_RESET_FAILED", client_id,
                                    f"Reset failed for {email}: {result['message']}")

        self.send_encrypted_message(client_id, {
            'type': 'password_reset_result',
            'message': result["message"],
            'success': result["success"]
        })


    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"🔒 Secure Chess Server started on {self.host}:{self.port}")
        print("Features:")
        print("  • Diffie-Hellman Key Exchange")
        print("  • AES-256-CBC Encryption")
        print("  • Perfect Forward Secrecy")
        print("  • End-to-End Encrypted Game Data")
        print("-" * 50)

        while True:
            try:
                client_socket, address = self.socket.accept()
                client_id = f"client_{len(self.clients)}"

                # Initialize crypto manager for this client
                crypto_manager = CryptoManager()

                self.clients[client_id] = {
                    'socket': client_socket,
                    'address': address,
                    'game_id': None,
                    'color': None,
                    'crypto': crypto_manager,
                    'secure': False  # Will be True after key exchange
                }

                thread = threading.Thread(target=self.handle_client, args=(client_id,))
                thread.daemon = True
                thread.start()

                print(f"🔗 Client {client_id} connected from {address}")
            except Exception as e:
                print(f"❌ Error accepting client: {e}")

    def handle_client(self, client_id):
        client = self.clients[client_id]
        socket_obj = client['socket']
        buffer = b""  # Use bytes buffer for encrypted data

        try:
            # Perform Diffie-Hellman key exchange
            if not self.perform_key_exchange(client_id):
                print(f"❌ Key exchange failed for {client_id}")
                return

            while True:
                data = socket_obj.recv(4096)  # Larger buffer for encrypted data
                if not data:
                    break

                buffer += data

                # Try to process complete messages
                while buffer:
                    try:
                        if client['secure']:
                            # For encrypted messages, we need to find message boundaries
                            # We'll use a simple length prefix: 4 bytes for message length
                            if len(buffer) < 4:
                                break

                            msg_length = int.from_bytes(buffer[:4], byteorder='big')
                            if len(buffer) < 4 + msg_length:
                                break

                            encrypted_msg = buffer[4:4 + msg_length]
                            buffer = buffer[4 + msg_length:]

                            # Decrypt the message
                            decrypted_data = client['crypto'].decrypt_message(encrypted_msg)
                            message = json.loads(decrypted_data)
                        else:
                            # For unencrypted key exchange messages
                            try:
                                message_str = buffer.decode('utf-8').strip()
                                message = json.loads(message_str)
                                buffer = b""
                            except json.JSONDecodeError:
                                if len(buffer) > 10000:
                                    buffer = b""
                                break

                        print(f"📨 Received from {client_id}: {message.get('type', 'unknown')}")
                        self.process_message(client_id, message)

                    except Exception as e:
                        print(f"❌ Error processing message from {client_id}: {e}")
                        if len(buffer) > 10000:
                            buffer = b""
                        break

        except Exception as e:
            print(f"❌ Error handling client {client_id}: {e}")
        finally:
            self.disconnect_client(client_id)

    def perform_key_exchange(self, client_id):
        """Perform Diffie-Hellman key exchange with client"""
        try:
            client = self.clients[client_id]
            socket_obj = client['socket']
            crypto = client['crypto']

            # Generate server's DH keypair
            server_public_key = crypto.generate_dh_keypair()

            # Send server's public key and DH parameters
            key_exchange_msg = {
                'type': 'key_exchange',
                'server_public_key': str(server_public_key),
                'dh_prime': str(CryptoManager.DH_PRIME),
                'dh_generator': str(CryptoManager.DH_GENERATOR)
            }

            socket_obj.send(json.dumps(key_exchange_msg).encode('utf-8'))
            print(f"🔑 Sent DH public key to {client_id}")

            # Receive client's public key
            data = socket_obj.recv(4096).decode('utf-8')
            client_response = json.loads(data)

            if client_response.get('type') != 'key_exchange_response':
                print(f"❌ Unexpected response from {client_id}: {client_response}")
                return False

            client_public_key = int(client_response['client_public_key'])

            # Compute shared secret
            crypto.compute_shared_secret(client_public_key)
            client['secure'] = True

            # Send confirmation
            confirmation = {'type': 'key_exchange_complete'}
            encrypted_confirmation = crypto.encrypt_message(json.dumps(confirmation))

            # Send with length prefix
            msg_length = len(encrypted_confirmation)
            socket_obj.send(msg_length.to_bytes(4, byteorder='big') + encrypted_confirmation)

            print(f"🔐 Key exchange completed for {client_id} - Connection secured")
            return True

        except Exception as e:
            print(f"❌ Key exchange failed for {client_id}: {e}")
            return False

    def send_encrypted_message(self, client_id, message):
        """Send encrypted message to client"""
        try:
            if client_id in self.clients:
                client = self.clients[client_id]
                socket_obj = client['socket']
                crypto = client['crypto']

                if client['secure']:
                    # Encrypt the message
                    message_str = json.dumps(message)
                    encrypted_data = crypto.encrypt_message(message_str)

                    # Send with length prefix
                    msg_length = len(encrypted_data)
                    socket_obj.send(msg_length.to_bytes(4, byteorder='big') + encrypted_data)

                    print(f"🔒 Sent encrypted message to {client_id}: {message.get('type', 'unknown')}")
                else:
                    # Fallback to unencrypted (should only happen during key exchange)
                    message_str = json.dumps(message)
                    socket_obj.send(message_str.encode('utf-8'))

                return True
            else:
                print(f"❌ Client {client_id} not found in clients list")
                return False
        except Exception as e:
            print(f"❌ Error sending encrypted message to {client_id}: {e}")
            self.disconnect_client(client_id)
            return False

    def process_message(self, client_id, message):
        msg_type = message.get('type')
        print(f"⚙️  Processing message from {client_id}: {msg_type}")

        # Authentication-related messages (allowed for non-authenticated users)
        if msg_type == 'register':
            self.handle_register(client_id, message)
        elif msg_type == 'login':
            self.handle_login(client_id, message)
        elif msg_type == 'password_reset_request':
            self.handle_password_reset_request(client_id, message)
        elif msg_type == 'password_reset':
            self.handle_password_reset(client_id, message)

        # Game-related messages (require authentication)
        elif msg_type == 'join_queue':
            if not self.clients[client_id].get('authenticated'):
                self.log_security_event("UNAUTHORIZED_ACCESS", client_id,
                                        "Attempted to join queue without authentication")
                self.send_error(client_id, "Please login first")
                return
            self.add_to_queue(client_id)
        elif msg_type == 'move':
            if not self.clients[client_id].get('authenticated'):
                self.log_security_event("UNAUTHORIZED_ACCESS", client_id,
                                        "Attempted to make move without authentication")
                self.send_error(client_id, "Please login first")
                return
            self.handle_move(client_id, message)
        elif msg_type == 'spectate':
            if not self.clients[client_id].get('authenticated'):
                self.log_security_event("UNAUTHORIZED_ACCESS", client_id,
                                        "Attempted to spectate without authentication")
                self.send_error(client_id, "Please login first")
                return
            self.handle_spectate(client_id, message)
        else:
            self.log_security_event("UNKNOWN_MESSAGE", client_id, f"Unknown message type: {msg_type}")
            print(f"❓ Unknown message type: {msg_type}")

    def add_to_queue(self, client_id):
        if client_id not in self.waiting_players:
            self.waiting_players.append(client_id)
            print(f"🎯 Added {client_id} to queue. Queue length: {len(self.waiting_players)}")
            self.send_encrypted_message(client_id, {'type': 'queue_joined', 'position': len(self.waiting_players)})

            if len(self.waiting_players) >= 2:
                print("🎮 Enough players in queue, creating game...")
                self.create_game()

    def create_game(self):
        if len(self.waiting_players) < 2:
            return

        player1_id = self.waiting_players.pop(0)
        player2_id = self.waiting_players.pop(0)

        print(f"🏁 Creating secure game between {player1_id} and {player2_id}")

        self.game_counter += 1
        game_id = f"game_{self.game_counter}"
        game = ChessGame(game_id)

        self.games[game_id] = game

        # Assign colors
        self.clients[player1_id]['game_id'] = game_id
        self.clients[player1_id]['color'] = PieceColor.WHITE
        self.clients[player2_id]['game_id'] = game_id
        self.clients[player2_id]['color'] = PieceColor.BLACK

        game.players[PieceColor.WHITE] = player1_id
        game.players[PieceColor.BLACK] = player2_id
        game.state = GameState.PLAYING

        print(f"🎲 Game {game_id} created, sending encrypted start messages...")

        # Notify players
        self.send_game_start(player1_id, game_id, PieceColor.WHITE)
        self.send_game_start(player2_id, game_id, PieceColor.BLACK)

        print(f"✅ Game start messages sent for {game_id}")

    def send_game_start(self, client_id, game_id, color):
        game = self.games[game_id]
        message = {
            'type': 'game_start',
            'game_id': game_id,
            'color': color.value,
            'board': game.get_board_state(),
            'current_player': game.current_player.value
        }
        self.send_encrypted_message(client_id, message)

    def handle_move(self, client_id, message):
        client = self.clients[client_id]
        game_id = client['game_id']

        if not game_id or game_id not in self.games:
            self.send_error(client_id, "Not in a game")
            return

        game = self.games[game_id]
        player_color = client['color']

        if game.current_player != player_color:
            self.send_error(client_id, "Not your turn")
            return

        from_row = message['from_row']
        from_col = message['from_col']
        to_row = message['to_row']
        to_col = message['to_col']
        promotion_piece = message.get('promotion_piece', None)

        print(f"♟️  Processing move from {client_id}: ({from_row},{from_col}) → ({to_row},{to_col})")

        result = game.make_move(from_row, from_col, to_row, to_col, player_color, promotion_piece)

        if result and result['success']:
            game_status = result['game_status']
            print(f"✅ Move successful, game status: {game_status['status']}")

            # Broadcast move to all players and spectators
            move_message = {
                'type': 'move_made',
                'from_row': from_row,
                'from_col': from_col,
                'to_row': to_row,
                'to_col': to_col,
                'board': game.get_board_state(),
                'current_player': game.current_player.value,
                'promotion': result.get('promotion', False),
                'promoted_to': result.get('promoted_to', None),
                'captured': result.get('captured', None),
                'game_status': game_status
            }

            for color, pid in game.players.items():
                self.send_encrypted_message(pid, move_message)

            for spectator_id in game.spectators:
                self.send_encrypted_message(spectator_id, move_message)

            # Handle game end
            if game_status['status'] in ['checkmate', 'stalemate']:
                game.state = GameState.FINISHED

                print(f"🏆 Game {game_id} ended: {game_status['status']}")
                print(f"   Current player after move: {game.current_player.value}")
                print(f"   Winner: {game_status.get('winner')}, Loser: {game_status.get('loser')}")

                # Create game end message
                end_message = {
                    'type': 'game_end',
                    'status': game_status['status'],
                    'winner': game_status.get('winner'),
                    'loser': game_status.get('loser'),
                    'message': game_status['message']
                }

                print(f"📢 Sending encrypted game end message: {end_message}")

                # Send to both players with verification
                players_notified = 0
                for color, pid in game.players.items():
                    if pid in self.clients:
                        result_text = "WINNER" if color.value == game_status.get('winner') else "LOSER"
                        print(f"   🏅 Sending to player {pid} (color: {color.value}) - {result_text}")

                        # Send the message multiple times with small delays
                        import time
                        for attempt in range(3):
                            try:
                                success = self.send_encrypted_message(pid, end_message)
                                if success:
                                    print(f"      ✅ Message sent successfully to {pid} on attempt {attempt + 1}")
                                    players_notified += 1
                                    time.sleep(0.1)
                                    break
                                else:
                                    print(f"      ❌ Failed to send message to {pid} on attempt {attempt + 1}")
                                    time.sleep(0.1)
                            except Exception as e:
                                print(f"      ❌ Exception sending to {pid} on attempt {attempt + 1}: {e}")
                                time.sleep(0.1)

                    else:
                        print(f"      ❌ Player {pid} not found in clients")

                print(f"📊 Successfully notified {players_notified} players")

                # Send to spectators
                for spectator_id in game.spectators:
                    if spectator_id in self.clients:
                        self.send_encrypted_message(spectator_id, end_message)

                print(f"🧹 Game {game_id} marked as finished - will be cleaned up later")
                self.start_cleanup_timer(game_id)
        else:
            print(f"❌ Invalid move from {client_id}")
            self.send_error(client_id, "Invalid move")

    def handle_spectate(self, client_id, message):
        """Handle spectator requests (future feature)"""
        print(f"👁️  Spectate request from {client_id} (not implemented)")
        self.send_error(client_id, "Spectating not yet implemented")

    def send_error(self, client_id, error_message):
        """Send encrypted error message to client"""
        print(f"⚠️  Sending error to {client_id}: {error_message}")
        self.send_encrypted_message(client_id, {'type': 'error', 'message': error_message})

    def cleanup_game(self, game_id):
        """Clean up a finished game"""
        if game_id in self.games:
            game = self.games[game_id]
            print(f"🧹 Cleaning up game {game_id}")

            # Reset all players' game state gently
            for color, pid in game.players.items():
                if pid in self.clients:
                    self.clients[pid]['game_id'] = None
                    self.clients[pid]['color'] = None
                    print(f"   🔄 Reset game state for player {pid}")

            del self.games[game_id]
            print(f"✅ Game {game_id} cleaned up successfully")

    def start_cleanup_timer(self, game_id):
        """Start a cleanup timer for a finished game"""
        import threading
        def delayed_cleanup():
            self.cleanup_game(game_id)

        # Wait 5 seconds before cleanup to let clients process messages
        threading.Timer(5.0, delayed_cleanup).start()
        print(f"⏰ Started cleanup timer for game {game_id}")

    def disconnect_client(self, client_id):
        """Handle client disconnection with enhanced logging"""
        if client_id in self.clients:
            client = self.clients[client_id]
            username = client.get('username', 'unknown')
            address = client.get('address', 'unknown')
            was_authenticated = client.get('authenticated', False)

            if was_authenticated:
                self.log_security_event("USER_DISCONNECT", client_id, f"User {username} disconnected")

            print(f"👋 Disconnecting client {client_id} (user: {username})")

            # Remove from waiting queue
            if client_id in self.waiting_players:
                self.waiting_players.remove(client_id)
                print(f"   🎯 Removed {client_id} from waiting queue")

            # Handle game disconnection more gracefully
            game_id = client.get('game_id')
            if game_id and game_id in self.games:
                game = self.games[game_id]
                print(f"   🎮 Client {client_id} was in game {game_id}")

                # Only notify opponent if the game is still active (not finished)
                if game.state == GameState.PLAYING:
                    print(f"   ⚡ Game {game_id} is still active, notifying opponent of disconnection")
                    for color, pid in game.players.items():
                        if pid != client_id and pid in self.clients:
                            print(f"      📢 Notifying {pid} that {client_id} disconnected")
                            self.send_encrypted_message(pid, {'type': 'opponent_disconnected'})

                    # Mark game for cleanup since it's an active disconnection
                    game.state = GameState.FINISHED
                    self.start_cleanup_timer(game_id)
                else:
                    print(f"   ✅ Game {game_id} is already finished, no need to notify opponent")

            # Close socket gently
            try:
                client['socket'].shutdown(socket.SHUT_RDWR)
            except:
                pass

            try:
                client['socket'].close()
            except:
                pass

            del self.clients[client_id]
            print(f"✅ Client {client_id} disconnected and cleaned up")


    def get_server_stats(self):
        """Get current server statistics"""

        stats = {
            'total_clients': len(self.clients),
            'active_games': len([g for g in self.games.values() if g.state == GameState.PLAYING]),
            'waiting_players': len(self.waiting_players),
            'total_games_created': self.game_counter,
            'authenticated_users': len([c for c in self.clients.values() if c.get('authenticated')]),
            'total_registered_users': len(self.user_db.users),
            'pending_reset_codes': len(self.user_db.password_reset_codes)
        }
        return stats


    def print_server_stats(self):
        """Print enhanced server statistics"""
        stats = self.get_server_stats()
        print(f"\n📊 Server Statistics:")
        print(f"   👥 Total Clients: {stats['total_clients']}")
        print(f"   🔐 Authenticated Users: {stats['authenticated_users']}")
        print(f"   🎮 Active Games: {stats['active_games']}")
        print(f"   ⏳ Waiting Players: {stats['waiting_players']}")
        print(f"   🎯 Total Games Created: {stats['total_games_created']}")
        print(f"   👤 Registered Users: {stats['total_registered_users']}")
        print(f"   🔑 Pending Reset Codes: {stats['pending_reset_codes']}")
        print("-" * 50)


class RateLimiter:
    def __init__(self):
        self.attempts = {}  # IP -> [(timestamp, action), ...]
        self.max_attempts = {
            'login': 5,  # 5 login attempts per 15 minutes
            'register': 3,  # 3 registration attempts per 15 minutes
            'reset': 3  # 3 password reset attempts per 15 minutes
        }
        self.time_window = 900  # 15 minutes in seconds

    def is_rate_limited(self, ip_address, action):
        """Check if IP is rate limited for specific action"""
        current_time = time.time()

        if ip_address not in self.attempts:
            self.attempts[ip_address] = []

        # Clean old attempts outside time window
        self.attempts[ip_address] = [
            (timestamp, act) for timestamp, act in self.attempts[ip_address]
            if current_time - timestamp < self.time_window
        ]

        # Count attempts for this action
        action_attempts = [
            timestamp for timestamp, act in self.attempts[ip_address]
            if act == action
        ]

        return len(action_attempts) >= self.max_attempts.get(action, 5)

    def record_attempt(self, ip_address, action):
        """Record an authentication attempt"""
        current_time = time.time()

        if ip_address not in self.attempts:
            self.attempts[ip_address] = []

        self.attempts[ip_address].append((current_time, action))


def main():
    """Main server function with enhanced error handling and user management"""
    print("🔒 Secure Chess Server v2.0 with User Authentication")
    print("=" * 60)

    # Install required dependency if not present
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

    # Create and start server
    server = SecureChessServer()

    try:
        # Set up periodic stats printing
        def print_stats_periodically():
            import time
            while True:
                time.sleep(300)  # Print stats every 5 minutes
                try:
                    server.print_server_stats()
                except:
                    pass

        stats_thread = threading.Thread(target=print_stats_periodically)
        stats_thread.daemon = True
        stats_thread.start()

        # Print initial server info
        print(f"\n🚀 Server starting on {server.host}:{server.port}")
        print("Features enabled:")
        print("  🔐 User authentication with secure password storage")
        print("  🔑 Password reset system")
        print("  🛡️ Rate limiting for authentication attempts")
        print("  📊 Enhanced security logging")
        print("  🎮 Encrypted multiplayer chess")

        if server.smtp_config:
            print("  📧 Email notifications for password reset")
        else:
            print("  📧 Email notifications: DISABLED (edit config.py to enable)")

        print(f"\n💾 User database: users.db")
        print(f"📋 Security log: security.log")
        print(f"👥 Registered users: {len(server.user_db.users)}")
        print("-" * 60)

        # Start the server
        server.start()

    except KeyboardInterrupt:
        print("\n🛑 Server shutting down gracefully...")
        print("📊 Final Statistics:")
        server.print_server_stats()

        # Close all client connections
        for client_id, client in list(server.clients.items()):
            try:
                if client.get('authenticated'):
                    server.log_security_event("SERVER_SHUTDOWN", client_id, f"User {client.get('username', 'unknown')}")
                client['socket'].close()
            except:
                pass

        # Close server socket
        try:
            server.socket.close()
        except:
            pass

        print("✅ Server shutdown complete")
        print(f"💾 User data preserved in users.db ({len(server.user_db.users)} users)")

    except Exception as e:
        print(f"❌ Server error: {e}")
        import traceback
        traceback.print_exc()

        # Try to save any pending database changes
        try:
            server.user_db.save_database()
            print("💾 Database saved before shutdown")
        except:
            pass


if __name__ == "__main__":
    main()
