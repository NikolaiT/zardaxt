from fastapi import FastAPI
import requests

app = FastAPI()

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.get("/classify")
def classify():
    return requests.get('http://0.0.0.0:8249/classify').json()

