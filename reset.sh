#!/bin/bash
# This is just for development purposes when you need to cleanup dirs
# made by the script

for dir in *_*_*; do
    if [ -d "$dir" ]; then
        
        if [[ "$dir" =~ ^[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}_(mssql|mysql|psql)_[0-9a-fA-F]{4}$ ]]; then
            
            read -p "Delete $dir? (y/n): " -n 1 reply
            echo "" 
            
            if [[ "$reply" =~ ^[Yy]$ ]]; then
                echo "Deleting..."
                rm -rf "$dir"
            else
                echo "Skipping..."
            fi
            
            echo "---"
        fi
    fi
done

echo "Cleanup complete!"
