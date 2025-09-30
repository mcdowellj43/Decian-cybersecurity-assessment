#!/bin/bash

# Script to fix all host-based module files
cd "$(dirname "$0")/host-based"

for file in *.go; do
    if [[ "$file" == "*.go" ]]; then
        continue  # No .go files found
    fi

    echo "Fixing $file..."

    # Change package declaration
    sed -i 's/^package modules$/package hostbased/' "$file"

    # Add modules import after logger import
    sed -i '/decian-agent\/internal\/logger/a\
	"decian-agent/internal/modules"' "$file"

    # Fix type references
    sed -i 's/\bTargetAware\b/modules.TargetAware/g' "$file"
    sed -i 's/\bModule\b/modules.Module/g' "$file"
    sed -i 's/\bModulePlugin\b/modules.ModulePlugin/g' "$file"
    sed -i 's/\bModuleInfo\b/modules.ModuleInfo/g' "$file"
    sed -i 's/\bAssessmentResult\b/modules.AssessmentResult/g' "$file"
    sed -i 's/\bCheckType/modules.CheckType/g' "$file"
    sed -i 's/\bRiskLevel/modules.RiskLevel/g' "$file"
    sed -i 's/\bBaseModule\b/modules.BaseModule/g' "$file"
    sed -i 's/\bDetermineRiskLevel\b/modules.DetermineRiskLevel/g' "$file"
    sed -i 's/\bRegisterPluginConstructor\b/modules.RegisterPluginConstructor/g' "$file"

done

echo "All files fixed!"