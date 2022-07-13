# README #

Open AI Web Services
This provides the web api rest methods for smart camera
Based on Flask Core UI project and sqlite implementation

### What is this repository for? ###

* Contains web methods for Open AI Smart Camera

* Version
* 

### How do I get set up? ###

To install execute:
1) virtualenv smartcam
2) source smartcam/bin/activate
3) pip install -r requirements.txt
4) export FLASK_APP=run.py
5) flask run --host=0.0.0.0 --port=5000

Test:
1) Import the file into Postman:
Test.postman_collection.json

SQLite:
db file is stored under:
openaiweb/apps/db.sqlite3

To view:
openaiweb/apps$ sqlite3 db.sqlite3
select * from devices;
select * from users;
select * from track_trn;
select * from user_track_mapper;