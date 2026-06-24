#!/bin/bash

rm data.db
sqlite3 "data.db" < data_schema.sql