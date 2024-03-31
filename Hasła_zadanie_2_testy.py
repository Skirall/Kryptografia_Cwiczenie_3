import unittest
import os
from tempfile import NamedTemporaryFile
from Hasła_zadanie_2 import PasswordManager

class TestPasswordManager(unittest.TestCase):
    def setUp(self):
        self.db_file = NamedTemporaryFile(delete=False)
        self.db_name = self.db_file.name
        self.password_manager = PasswordManager(self.db_name)

    def tearDown(self):
        self.db_file.close()
        os.unlink(self.db_name)

    def test_add_user(self): # Testowanie dodawania użytkownika
        self.assertTrue(self.password_manager.add_user('test_user', 'test_password'))
        self.assertFalse(self.password_manager.add_user('test_user', 'test_password'))

    def test_verify_password(self): # Testowanie sprawdzania hasła
        self.password_manager.add_user('test_user', 'test_password')
        self.assertTrue(self.password_manager.verify_password('test_user', 'test_password'))
        self.assertFalse(self.password_manager.verify_password('test_user', 'wrong_password'))

    def test_generate_salt(self): # Testowanie generowania soli
        salt1 = self.password_manager.generate_salt()
        salt2 = self.password_manager.generate_salt()
        self.assertNotEqual(salt1, salt2)

    def test_hash_password(self): # Testowanie hasowania
        password = 'test_password'
        salt = 'test_salt'
        hashed_password = self.password_manager.hash_password(password, salt)
        self.assertIsNotNone(hashed_password)
        self.assertNotEqual(hashed_password, password)  # Sprawdza czy hasz hasła jest inne niż hash oryginalnego hasła

if __name__ == '__main__':
    unittest.main()
