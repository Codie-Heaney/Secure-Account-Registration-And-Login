import os
import csv
import hashlib
import random
import string
import jwt
from datetime import datetime
from time import sleep
from cryptography.fernet import Fernet
from dateutil.relativedelta import relativedelta

LINE_UP = '\033[1A'
LINE_CLEAR = '\x1b[2K'
SLEEP_READING_TIME = 10
SECRET = 'secret'

class InvalidTokenHash(Exception):
    pass
class InvalidTokenSigniture(Exception):
    pass
class InvalidTokenFile(Exception):
    pass
class InvalidTokenEnding(Exception):
    pass
class NoUserFile(Exception):
    pass
class NoTokenFile(Exception):
    pass
class LoginDetailsIncorrect(Exception):
    pass
class IncorrectTokenLoginDetails(Exception):
    pass

class FileSystem():
    def __init__(self):
        self.key_path = 'aeskey.key'
     
    def write_user_csv(self, username, usersalt, password, passsalt):
      with open('users.csv', 'a', newline='') as userscsv:
          fieldnames = ['username', 'usersalt','password', 'passsalt']
          writer = csv.DictWriter(userscsv, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL, fieldnames=fieldnames)
          writer.writerow({'username':username, 'usersalt':usersalt,'password':password, 'passsalt': passsalt})
    
    def write_token_csv(self, token):
      with open('token.csv', 'a', newline='') as userscsv:
          fieldnames = ['token']
          writer = csv.DictWriter(userscsv, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL, fieldnames=fieldnames)
          writer.writerow({'token':token})

    def check_file(self, path):
        return os.path.isfile(path)
    
    def create_token_file(self, path, token):
        with open(path + ".token", 'w') as tokenfile:
            tokenfile.write(token)
    
    def open_token_file(self, path):
        if(self.check_file(path)):
            try:
                with open(path, "r") as tokenfile:
                    token = tokenfile.read()
                return token
            except:
                raise InvalidTokenEnding
        else:
            raise InvalidTokenFile
    
    def create_key_file(self, key):
        with open(self.key_path, 'wb') as keyfile:
            keyfile.write(key)

    def open_key_file(self):
        if self.check_file(self.key_path):
            with open(self.key_path, "rb") as keyfile:
                key = keyfile.read()
            return key
        else:
            return False
    
    def open_user_file(self, username, password, token = True):

        if(not token): hash = Hash()

        if(self.check_file('users.csv')):
            with open('users.csv', 'r') as userfile:
                data = csv.reader(userfile)
                for line in data:
                    if(token):
                        if username.decode("utf-8") == line[0] and password.decode("utf-8") == line[2]:
                            return True
                    if(not token):
                        username_salted = username + line[1]
                        password_salted = password + line[3]
                        username_hash = hash.hash_text_no_salt_gen(username_salted)
                        password_hash = hash.hash_text_no_salt_gen(password_salted)
                        if username_hash == line[0] and password_hash == line[2]:
                            return True
                else:
                    return False
        else:
            raise NoUserFile

    def check_token_file(self, token_data):
        hash = Hash()
        token_hash = hash.hash_text_no_salt_gen(token_data)
        if(self.check_file('token.csv')):
            with open('token.csv', 'r') as tokenfile:
                data = csv.reader(tokenfile)
                for line in data:
                    if token_hash == line[0]:
                        return True
            return False
        else:
            raise NoTokenFile

class AES():
     def __init__(self):
          self.datakey = self._create_key()
     
     def _create_key(self):
        filesystem = FileSystem()
        key = filesystem.open_key_file()

        if key == False:
            key = Fernet.generate_key()
            filesystem.create_key_file(key)
            return key
        else:
            return key

     def encrypt_text(self, aes_string):
         key = Fernet(self.datakey)
         byte_string = aes_string.encode('utf-8')
         return key.encrypt(byte_string)
     
     def decrypt_text(self, encrypted_string):
         key = Fernet(self.datakey)
         return key.decrypt(encrypted_string)
     
class Hash():
    def __init__(self):
        pass

    def hash_text(self, hash_string):
        sha256 = hashlib.sha256()
        salt = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))

        hash_string = hash_string + salt
        hash_string = hash_string.encode('utf-8')
        sha256.update(hash_string)
        return {'hash': sha256.hexdigest(), 'salt': salt}
    
    def hash_text_no_salt_gen(self, hash_string):
        sha256 = hashlib.sha256()
        hash_string = hash_string.encode('utf-8')
        sha256.update(hash_string)
        return sha256.hexdigest()
    
class Token():
    def __init__(self):
        pass

    def create_token(self, username, password, access):
        current_date = datetime.today()
        aes = AES()

        expire_date = (current_date + relativedelta(days=7)).strftime("%m/%d/%Y")
        token_payload = {'username': aes.encrypt_text(username).decode("utf-8"),
                        'password': aes.encrypt_text(password).decode("utf-8"), 
                        'access': aes.encrypt_text(access).decode("utf-8"), 
                        'expire': aes.encrypt_text(expire_date).decode("utf-8")}

        token_data = jwt.encode(payload=token_payload, key=SECRET, algorithm="HS256")
        return token_data
    
    def decode_token(self, token):
        data = jwt.decode(jwt=token,
                          key=SECRET,
                          algorithms=["HS256"])
        return data

class CreateUser():
    def __init__(self):
        pass

    def create_user(self):
        filesystem = FileSystem()
        hash = Hash()
        token = Token()

        username_inp = input("Enter a username: ")
        password_inp = input("Enter a password: ")
        access_level = input("Enter access level for this user: ")
        token_name = input("Enter a name for the token file: ")

        username_hash = hash.hash_text(username_inp)
        password_hash = hash.hash_text(password_inp)

        filesystem.write_user_csv(username_hash['hash'], username_hash['salt'], password_hash['hash'], password_hash['salt'])
        user_token = token.create_token(username_hash['hash'], password_hash['hash'], access_level)
        token_hash = hash.hash_text_no_salt_gen(user_token)
        filesystem.write_token_csv(token_hash)
        filesystem.create_token_file(token_name+"_"+str(random.randint(0, 9999)), user_token)

def logintoken():

    filesystem = FileSystem()
    token = Token()
    aes = AES()

    token_path = input("Enter token file path: ")
    token_file = filesystem.open_token_file(token_path)

    if(not filesystem.check_token_file(token_file)):
        raise InvalidTokenHash
    
    print("Token hash matches!\n")

    try:
        token_data = token.decode_token(token_file)
        print("Token signiture correct!\n")
    except:
        raise InvalidTokenSigniture
    
    token_username = aes.decrypt_text(token_data['username'])
    token_password = aes.decrypt_text(token_data['password'])
    token_access = aes.decrypt_text(token_data['access']).decode('utf-8')
    
    if(not filesystem.open_user_file(token_username, token_password)):
        raise LoginDetailsIncorrect
    
    print("Token details correct!\n")

    token_date = aes.decrypt_text(token_data['expire']).decode('utf-8')
    token_date = datetime.strptime(token_date, "%m/%d/%Y")
    if token_date < datetime.today():
        print("Token expired, please re-enter login details to generate a new token\n")
        if(login()):

            hash = Hash()

            new_token = token.create_token(token_username.decode('utf-8'), token_password.decode('utf-8'), token_access)
            new_token_hash = hash.hash_text_no_salt_gen(new_token)
            filesystem.write_token_csv(new_token_hash)
            filesystem.create_token_file(token_path.replace(".token",""), new_token)

            print("Token updated!\n")

            return

        else:
            raise IncorrectTokenLoginDetails
    print("Token valid for: "+ str(token_date - datetime.today()))
    
    print("Login Successful")

def login():
    filesystem = FileSystem()
    username_inp = input("Enter a username: ")
    password_inp = input("Enter a password: ")
    return filesystem.open_user_file(username_inp, password_inp, False)

def loginuserpass():
    if(login()):
        print("Login Successful")
    else:
        raise LoginDetailsIncorrect

def user_register():
    createuser = CreateUser()
    createuser.create_user()

    print("New user created!")
    sleep(SLEEP_READING_TIME)

def clear_all():
    os.system('cls')

def clear_line(clear_total = 1):
    for i in range(clear_total):
        print(LINE_UP, end=LINE_CLEAR)

MENU_ITEMS = {
    0:{
        'name':"0) Login with token",
        'call': logintoken
    },
    1:{
        'name':'1) Login with username and password',
        'call':loginuserpass
    }, 
    2:{
        'name':"2) Create new user",
        'call': user_register
    }
}

def print_menu():
    print("--Start Menu--")
    for item in range(0, len(MENU_ITEMS)):
        print(MENU_ITEMS[item]['name'])

def mainloop():
    while True:
        clear_all()
        print_menu()
        user_inp = input("\nEnter menu number: ")
        MENU_ITEMS[int(user_inp)]['call']()
        try:
            #MENU_ITEMS[int(user_inp)]['call']()
            pass
        except InvalidTokenFile:
            print("Token file doesn't exist!")
        except InvalidTokenHash:
            print("Token has been altered!")
        except InvalidTokenSigniture:
            print("Token file signiture is incorrect!")
        except NoUserFile:
            print("No users have been registered yet!")
        except NoTokenFile:
            print("No registred tokens exist!")
        except InvalidTokenEnding:
            print("Token file couldn't be accessed!")
        except LoginDetailsIncorrect:
            print("Login details incorrect!")
        except IncorrectTokenLoginDetails:
            print("Login details incorrect!")
        except:
            print("Please enter a valid menu number!")
        
        print("\nReturning to main menu...")
        sleep(SLEEP_READING_TIME)

mainloop()