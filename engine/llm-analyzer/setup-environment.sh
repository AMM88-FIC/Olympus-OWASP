#!/usr/bin/env bash
set -e

PROJECT="apk-analyzer"

echo "Creating project structure: $PROJECT/"

mkdir -p "$PROJECT"/{storage/{uploads,artifacts},tools,app/{extraction,models,api},tests}

# Root files
touch "$PROJECT/README.md"
touch "$PROJECT/config.py"

cat > "$PROJECT/requirements.txt" << 'EOF'
fastapi
uvicorn[standard]
androguard
python-multipart
pydantic
EOF

# App package files
touch "$PROJECT/app/__init__.py"
touch "$PROJECT/app/main.py"

# Extraction layer
touch "$PROJECT/app/extraction/__init__.py"
touch "$PROJECT/app/extraction/coordinator.py"
touch "$PROJECT/app/extraction/apktool_runner.py"
touch "$PROJECT/app/extraction/jadx_runner.py"
touch "$PROJECT/app/extraction/androguard_runner.py"

# Models layer
touch "$PROJECT/app/models/__init__.py"
touch "$PROJECT/app/models/extraction.py"

# API layer
touch "$PROJECT/app/api/__init__.py"
touch "$PROJECT/app/api/routes.py"

# Tests
touch "$PROJECT/tests/test_extraction.py"

# Placeholder for tools (downloaded separately)
touch "$PROJECT/tools/.gitkeep"

echo ""
echo "Done. Structure created:"
find "$PROJECT" | sort | sed 's|[^/]*/|  |g'

echo ""
echo "Next steps:"
echo "  1. cd $PROJECT"
echo "  2. python3 -m venv venv && source venv/bin/activate"
echo "  3. pip install -r requirements.txt"
echo "  4. Download apktool.jar → tools/apktool.jar"
echo "  5. Download jadx → tools/jadx/"
