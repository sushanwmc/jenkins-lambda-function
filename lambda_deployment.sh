#!/usr/bin/env sh
echo "Initializing the lambda deployment package"

if [ -d "$1" ]; then
  echo "$1 folder already exists. Removing in Process"
  rm -rf "$1" ;
  echo "Existing $$1  folder removed"

  mkdir "$1";
  echo "Created new $1 folder"

else
  echo "Creating $1 folder"
  mkdir "$1"

fi

echo "Copy all the contents to folder $1"
sudo rsync -a "$(pwd)"/* ./"$1" --exclude "$1" --exclude "data"
cp .env "$1"

echo "Installing required libraries"
cd "$1" || exit
pip install -r requirements.txt --target="$(pwd)"

echo "Compressing all the contents of folder"
zip -r "$1" .
mv "$1.zip" ../

echo "Removing the folder: $1"
cd ..
rm -rf "$1"
