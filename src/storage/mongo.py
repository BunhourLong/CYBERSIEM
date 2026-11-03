import os
from dataclasses import asdict

from pymongo import MongoClient

MONGO_URI = os.getenv("MONGO_URI", "mongodb://sentinel:sentinelpass@localhost:27017")

client = MongoClient(MONGO_URI)
db = client["sentinel_ids"]
events_collection = db["events"]


def save_event(event):
    events_collection.insert_one(asdict(event))
