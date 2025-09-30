#!/bin/bash

# Script to clean up the over-prefixed modules
cd "$(dirname "$0")/host-based"

for file in *.go; do
    if [[ "$file" == "*.go" ]]; then
        continue  # No .go files found
    fi

    echo "Cleaning up $file..."

    # Remove duplicate modules imports
    sed -i '/decian-agent\/internal\/modules/{N;s/\n.*decian-agent\/internal\/modules//;}' "$file"

    # Fix double-prefixing
    sed -i 's/modules\.modules\./modules./g' "$file"

    # Fix struct field syntax (modules.CheckType: should be CheckType:)
    sed -i 's/modules\.CheckType:/CheckType:/g' "$file"
    sed -i 's/modules\.RiskLevel:/RiskLevel:/g' "$file"
    sed -i 's/result\.modules\.RiskLevel/result.RiskLevel/g' "$file"

done

echo "Cleanup complete!"