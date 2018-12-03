#!/bin/bash

cd experiments/exp1/
rm -rf content_json
rm -rf flow_json
cd ../..
python3 DeviceDetector.py experiments/exp1
