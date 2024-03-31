import sqlite3
import hashlib
import secrets

class PasswordManager:
    def __init__(self, db_name='passwords.db'): # stworzenie połączenia z bazą danych
        self.conn = sqlite3.connect(db_name)
        self.create_table()

    def __del__(self): # zamknięcie połaczenia
        self.conn.close()

    def create_table(self): # tworzenie tabeli
        self.conn.execute('''CREATE TABLE IF NOT EXISTS users
                             (username TEXT PRIMARY KEY, hashed_password TEXT, salt TEXT)''')

    def generate_salt(self): # generowanie soli
        return secrets.token_hex(16)

    def hash_password(self, password, salt): # Hashowanie przez sha256
        """
        Funkcja Hashująca
        
        parametry: 
        password (any) - hasło
        salt (any) - sól

        zwraca:
        hased_password - zakodowane hasło
        """
        salted_password = password + salt
        hashed_password = hashlib.sha256(salted_password.encode()).hexdigest()
        return hashed_password

    def add_user(self, username, password):
        """
        Funkcja dodająca użytkownika
        
        parametry: 
        username (any) - użytkownik
        password (any) - hasło

        zwraca:
        true/ false (funkcja sama dodaje lub nie użytkownika i na podstawie tego zwraca bool'a)
        """
        # Sprawda, czy użytkownik o podanej nazwie już istnieje
        cursor = self.conn.execute("SELECT COUNT(*) FROM users WHERE username=?", (username,))
        if cursor.fetchone()[0] > 0:
            print("Użytkownik o nazwie '{}' już istnieje.".format(username))
            return False
        else:
            # Dodaje nowego użytkownika do bazy danych
            salt = self.generate_salt()
            hashed_password = self.hash_password(password, salt)
            self.conn.execute("INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)",
                              (username, hashed_password, salt))
            self.conn.commit()
            print("Dodano nowego użytkownika o nazwie '{}'.".format(username))
            return True

    def verify_password(self, username, password):
        
        cursor =  """
        Funkcja weryfikująca hasło
        
        parametry: 
        username (any) - użytkownik
        password (any) - hasło

        zwraca:
        True/false (funkcja sprawdza, czy hasło jest poprawne i na podstawie tego zwraca bool'a)
        """
        self.conn.execute("SELECT hashed_password, salt FROM users WHERE username=?", (username,))
        row = cursor.fetchone()
        if row:
            hashed_password_stored = row[0]
            salt = row[1]
            hashed_password_input = self.hash_password(password, salt)
            if hashed_password_input == hashed_password_stored:
                return True
        return False

# Przykład użycia:
if __name__ == "__main__":
    password_manager = PasswordManager()
    password_manager.add_user('joanna_kowalska', 'tajne_haslo_drugie')

    if password_manager.verify_password('jan_kowalski', 'tajne_haslo'):
        print("Hasło jest poprawne!")
    else:
        print("Hasło jest niepoprawne!")
