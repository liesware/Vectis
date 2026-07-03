#!/bin/bash

rm data.db
sqlite3 "data.db" < sqlite_schema.sql