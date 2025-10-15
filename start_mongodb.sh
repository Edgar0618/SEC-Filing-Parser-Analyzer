#!/bin/bash

# Check if MongoDB is already running
if pgrep -x "mongod" > /dev/null; then
    echo "MongoDB is already running!"
else
    echo "Starting MongoDB..."
    
    # Try to start MongoDB using brew (macOS)
    if command -v brew &> /dev/null; then
        brew services start mongodb/brew/mongodb-community
    else
        # Try to start MongoDB directly
        mongod --dbpath ./data/db &
    fi
    
    echo "MongoDB started! You can now use the app."
fi
