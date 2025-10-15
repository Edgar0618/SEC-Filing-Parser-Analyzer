try:
    from pymongo import MongoClient, errors
    HAS_PYMONGO = True
except Exception:
    HAS_PYMONGO = False
    # Minimal shim for DuplicateKeyError when pymongo isn't installed
    class errors:
        class DuplicateKeyError(Exception):
            pass
    MongoClient = None

from PasswordHashing import hash_password
import datetime
import os

def createConnection():
    # Try to get MongoDB URI from environment variable (for Vercel deployment)
    # Fall back to localhost for local development
    mongodb_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')

    # If pymongo not present, use mock DB immediately
    if not HAS_PYMONGO:
        print("PyMongo not installed. Using in-memory mock database.")
        return MockDatabase()

    try:
        client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
        # Test the connection
        client.server_info()
        db = client.userDatabase
        return db
    except Exception as e:
        print("MongoDB connection failed: " + str(e))
        # Return a mock database for development/testing
        return MockDatabase()

class MockDatabase:
    """Mock database for development when MongoDB is not available"""
    def __init__(self):
        self.users = MockCollection()
        print("Using mock database - MongoDB not available")
    
    def list_collection_names(self):
        return ['users'] if self.users.data else []

    def create_collection(self, name):
        if not hasattr(self, name):
            setattr(self, name, MockCollection())
        return getattr(self, name)

class MockCollection:
    def __init__(self):
        self.data = []
        self.indexes = set()
    
    def insert_one(self, document):
        # Check for duplicate usernames
        for user in self.data:
            if user.get('username') == document.get('username'):
                raise errors.DuplicateKeyError("Username already exists")
        self.data.append(document)
        return {'inserted_id': len(self.data)}
    
    def find_one(self, query):
        for user in self.data:
            match = True
            for key, value in query.items():
                if user.get(key) != value:
                    match = False
                    break
            if match:
                return user
        return None
    
    def find(self, query=None):
        if query is None:
            return self.data
        results = []
        for user in self.data:
            match = True
            for key, value in query.items():
                if user.get(key) != value:
                    match = False
                    break
            if match:
                results.append(user)
        return results
    
    def update_one(self, query, update):
        for user in self.data:
            match = True
            for key, value in query.items():
                if user.get(key) != value:
                    match = False
                    break
            if match:
                # Handle $push operations
                if '$push' in update:
                    for field, value in update['$push'].items():
                        if field not in user:
                            user[field] = []
                        user[field].append(value)
                # Handle $set operations
                elif '$set' in update:
                    user.update(update['$set'])
                return {'modified_count': 1}
        return {'modified_count': 0}
    
    def create_index(self, field, **kwargs):
        self.indexes.add(field)
        return field
    
    def list_collection_names(self):
        return ['users'] if self.data else []

def createCollection(db):
    if "users" not in db.list_collection_names():
        db.create_collection("users")
        db.users.create_index("username", unique=True)
        print("Collection 'users' created successfully.")
    else:
        print("Collection 'users' already exists.")

def registerUser(db, username, password, name, date_of_birth, is_admin=False):
    hashed_password = hash_password(password)
    try:
        db.users.insert_one({
            "username": username,
            "password": hashed_password,
            "name": name,
            "date_of_birth": date_of_birth,
            "is_admin": is_admin,
            "scan_history": []
        })
        return True, "User " + username + " registered successfully!"
    except errors.DuplicateKeyError:
        return False, "Username already exists. Try a different one."

def login(db, username, hashed_password):
    user = db.users.find_one({"username": username, "password": hashed_password})
    if user:
        print(f"Welcome back {user['name']}!")
        return True, user
    else:
        print("Invalid username or password")
        return False, None

def logScan(db, username, filename):
    # Record the date and time of the scan along with the filename
    scan_entry = {
        'date': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'filename': filename
    }
    # Append this entry to the user's scan_history
    db.users.update_one(
        {'username': username},
        {'$push': {'scan_history': scan_entry}}
    )