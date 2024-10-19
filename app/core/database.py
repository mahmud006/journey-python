from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017")
db = client["mydatabase"]

# Access collections
users_collection = db["users"]
