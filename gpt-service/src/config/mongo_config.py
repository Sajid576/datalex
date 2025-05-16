from src.utils.env import get_env
from pymongo import MongoClient
from pymongo.server_api import ServerApi

def get_mongodb_uri():
    username = get_env("MONGO_INITDB_ROOT_USERNAME")
    password = get_env("MONGO_INITDB_ROOT_PASSWORD")
    database = get_env("MONGO_INITDB_DATABASE")
    replica_set = get_env("MONGO_REPLICA_SET")
    
    return f"mongodb://{username}:{password}@localhost:27017/{database}?replicaSet={replica_set}"

def get_db_client():
    try:
        client = MongoClient(
            get_mongodb_uri(),
            server_api=ServerApi('1'),
            serverSelectionTimeoutMS=5000
        )
        
        # Test the connection
        client.admin.command('ping')
        print("Successfully connected to MongoDB.")
        return client
        
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        raise

def get_database():
    client = get_db_client()
    return client[get_env("MONGO_INITDB_DATABASE")]

# Example usage of the database connection
def init_db():
    try:
        db = get_database()
        # You can initialize collections here if needed
        return db
    except Exception as e:
        print(f"Failed to initialize database: {e}")
        raise